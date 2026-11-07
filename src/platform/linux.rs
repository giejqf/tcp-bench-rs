//! The only raw socket FFI boundary. AsyncFd owns every descriptor.
use crate::{Error, Result, packet::ProbePacket};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
};
use tokio::io::unix::AsyncFd;

pub struct RawSocket {
    socket: AsyncFd<Socket>,
    v6: bool,
}

/// Cooked packet capture retains full IP headers and checksum-offload metadata.
/// No promiscuous mode. A classic socket filter admits only packets destined to
/// our selected local address; the portable codec performs detailed correlation.
pub struct CaptureSocket {
    socket: AsyncFd<Socket>,
}
impl CaptureSocket {
    pub fn new(source: IpAddr, source_port: u16) -> Result<Self> {
        let ethertype: u16 = if source.is_ipv6() { 0x86dd } else { 0x0800 };
        let socket = Socket::new(
            Domain::from(libc::AF_PACKET),
            Type::DGRAM,
            Some(Protocol::from(ethertype.to_be() as i32)),
        )
        .map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                Error::Privilege(e)
            } else {
                Error::io("create packet receiver", e)
            }
        })?;
        socket
            .set_nonblocking(true)
            .map_err(|e| Error::io("nonblocking packet receiver", e))?;
        let enabled: libc::c_int = 1;
        // SAFETY: a live socket and initialized int of the correct option size.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_AUXDATA,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(Error::io(
                "enable packet checksum metadata",
                io::Error::last_os_error(),
            ));
        }
        let (offset, address) = match source {
            IpAddr::V4(ip) => (16, ip.octets().to_vec()),
            IpAddr::V6(ip) => (24, ip.octets().to_vec()),
        };
        let mut instructions = Vec::new();
        for (index, word) in address.chunks_exact(4).enumerate() {
            instructions.push(libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: offset + index as u32 * 4,
            }); // LD W ABS
            instructions.push(libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: u32::from_be_bytes(word.try_into().expect("four-byte chunk")),
            }); // JEQ
            instructions.push(libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0,
            }); // RET reject
        }
        if source.is_ipv4() {
            // ICMP errors are small and need their quoted tuples inspected in Rust.
            instructions.extend([
                libc::sock_filter {
                    code: 0x30,
                    jt: 0,
                    jf: 0,
                    k: 9,
                }, // LD B protocol
                libc::sock_filter {
                    code: 0x15,
                    jt: 5,
                    jf: 0,
                    k: 1,
                }, // ICMP -> accept
                libc::sock_filter {
                    code: 0x15,
                    jt: 0,
                    jf: 5,
                    k: 6,
                }, // non-TCP -> reject
                libc::sock_filter {
                    code: 0xb1,
                    jt: 0,
                    jf: 0,
                    k: 0,
                }, // LDX IPv4 IHL
                libc::sock_filter {
                    code: 0x48,
                    jt: 0,
                    jf: 0,
                    k: 2,
                }, // LD H [IHL+2]: destination port
                libc::sock_filter {
                    code: 0x15,
                    jt: 1,
                    jf: 0,
                    k: source_port as u32,
                },
                libc::sock_filter {
                    code: 0x06,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
            ]);
        } else {
            // IPv6 TCP without extension headers can be filtered cheaply. Keep
            // extension-header packets for the bounded portable header walker.
            instructions.extend([
                libc::sock_filter {
                    code: 0x30,
                    jt: 0,
                    jf: 0,
                    k: 6,
                },
                libc::sock_filter {
                    code: 0x15,
                    jt: 0,
                    jf: 3,
                    k: 6,
                },
                libc::sock_filter {
                    code: 0x28,
                    jt: 0,
                    jf: 0,
                    k: 42,
                },
                libc::sock_filter {
                    code: 0x15,
                    jt: 1,
                    jf: 0,
                    k: source_port as u32,
                },
                libc::sock_filter {
                    code: 0x06,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
            ]);
        }
        instructions.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 65535,
        });
        // Destination for the IPv4 non-TCP/non-ICMP branch.
        instructions.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0,
        });
        let filter = libc::sock_fprog {
            len: instructions.len() as u16,
            filter: instructions.as_mut_ptr(),
        };
        // SAFETY: the kernel copies the valid classic BPF program synchronously;
        // both the descriptor and instruction allocation remain live for the call.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                (&filter as *const libc::sock_fprog).cast(),
                std::mem::size_of_val(&filter) as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(Error::io(
                "attach packet destination filter",
                io::Error::last_os_error(),
            ));
        }
        // SAFETY: owned socket descriptor is stable until AsyncFd drops it.
        let socket = unsafe { AsyncFd::register(socket) }
            .map_err(|e| Error::io("register packet receiver", e.into_parts().1))?;
        Ok(Self { socket })
    }
    pub async fn receive(&self, buffer: &mut [u8]) -> Result<(usize, bool)> {
        loop {
            let mut ready = self
                .socket
                .readable()
                .await
                .map_err(|e| Error::io("packet readable", e))?;
            let result = ready.try_io(|fd| {
                let mut iov = libc::iovec {
                    iov_base: buffer.as_mut_ptr().cast(),
                    iov_len: buffer.len(),
                };
                // usize provides cmsghdr alignment; enough space for auxiliary data.
                let mut control = [0usize; 32];
                // SAFETY: msghdr has no invalid zero representation; pointers below
                // reference live writable allocations for the indicated lengths.
                let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
                message.msg_iov = &mut iov;
                message.msg_iovlen = 1;
                message.msg_control = control.as_mut_ptr().cast();
                message.msg_controllen = std::mem::size_of_val(&control);
                // SAFETY: exclusive writable buffers, live fd, no pointer retention.
                let n = unsafe { libc::recvmsg(fd.get_ref().as_raw_fd(), &mut message, 0) };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
                    return Ok((0, false));
                }
                let mut offloaded = false;
                // SAFETY: recvmsg initialized the bounded control area; CMSG traversal
                // checks each next header against msg_controllen.
                unsafe {
                    let mut header = libc::CMSG_FIRSTHDR(&message);
                    while !header.is_null() {
                        if (*header).cmsg_level == libc::SOL_PACKET
                            && (*header).cmsg_type == libc::PACKET_AUXDATA
                            && (*header).cmsg_len >= libc::CMSG_LEN(4) as usize
                        {
                            // tpacket_auxdata begins with native-endian u32 tp_status.
                            let status =
                                std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<u32>());
                            offloaded = status & ((1 << 3) | (1 << 7)) != 0; // CSUMNOTREADY or CSUM_VALID
                        }
                        header = libc::CMSG_NXTHDR(&message, header);
                    }
                }
                Ok((n as usize, offloaded))
            });
            match result {
                Ok(result) => return result.map_err(|e| Error::io("receive packet", e)),
                Err(_) => continue,
            }
        }
    }
}
impl RawSocket {
    pub fn new(source: IpAddr, protocol: u8) -> Result<Self> {
        let v6 = source.is_ipv6();
        let socket = Socket::new(
            if v6 { Domain::IPV6 } else { Domain::IPV4 },
            Type::RAW,
            Some(Protocol::from(protocol as i32)),
        )
        .map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                Error::Privilege(e)
            } else {
                Error::io("create raw socket", e)
            }
        })?;
        socket
            .set_nonblocking(true)
            .map_err(|e| Error::io("nonblocking raw socket", e))?;
        socket
            .bind(&SocketAddr::new(source, 0).into())
            .map_err(|e| Error::io("bind raw source", e))?;
        if !v6 {
            socket
                .set_header_included_v4(true)
                .map_err(|e| Error::io("IP_HDRINCL", e))?;
        } else {
            // Never silently fragment a requested large IPv6 probe.
            let value: libc::c_int = 1;
            // SAFETY: socket is live; value points to an initialized int of the provided length.
            let rc = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_DONTFRAG,
                    (&value as *const libc::c_int).cast(),
                    std::mem::size_of_val(&value) as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(Error::io("IPV6_DONTFRAG", io::Error::last_os_error()));
            }
        }
        Ok(Self {
            // SAFETY: AsyncFd exclusively owns this socket. Its descriptor is never
            // closed, replaced, or re-registered before AsyncFd is dropped.
            socket: unsafe { AsyncFd::register(socket) }
                .map_err(|e| Error::io("register raw socket", e.into_parts().1))?,
            v6,
        })
    }
    pub async fn send(&self, packet: &ProbePacket, bytes: &[u8]) -> Result<tokio::time::Instant> {
        if self.v6 {
            self.socket
                .get_ref()
                .set_unicast_hops_v6(packet.hop_limit as u32)
                .map_err(|e| Error::io("IPv6 hop limit", e))?;
        }
        let payload = if self.v6 { &bytes[40..] } else { bytes };
        let address = SockAddr::from(SocketAddr::new(packet.destination, 0));
        loop {
            let mut ready = self
                .socket
                .writable()
                .await
                .map_err(|e| Error::io("raw writable", e))?;
            match ready.try_io(|fd| {
                let sent_at = tokio::time::Instant::now();
                fd.get_ref()
                    .send_to(payload, &address)
                    .map(|n| (n, sent_at))
            }) {
                Ok(Ok((n, sent_at))) if n == payload.len() => return Ok(sent_at),
                Ok(Ok(_)) => {
                    return Err(Error::io(
                        "send raw datagram",
                        io::Error::new(io::ErrorKind::WriteZero, "partial datagram"),
                    ));
                }
                Ok(Err(e)) => return Err(Error::io("send raw datagram (check route and MTU)", e)),
                Err(_) => continue,
            }
        }
    }
}
