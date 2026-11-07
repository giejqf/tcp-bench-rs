mod support;
use std::{sync::Arc, time::Duration};
use tcp_bench_rs::{
    http::Client,
    scheduler::Cancellation,
    throughput::{self, TransferConfig},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn tls_configs() -> (rustls::ServerConfig, Client) {
    let cert =
        rustls::pki_types::CertificateDer::from(include_bytes!("fixtures/server.der").to_vec());
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
        include_bytes!("fixtures/server-key.der").to_vec(),
    );
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key.into())
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    (server, Client::with_roots(roots))
}

#[tokio::test]
async fn bearer_header_requires_tls_and_does_not_follow_redirects() {
    let (config, client) = tls_configs();
    for (url, token) in [
        ("http://127.0.0.1:1/", "test-token"),
        ("https://fixed.test/", "bad\r\nInjected: header"),
    ] {
        assert!(
            client
                .get_with_bearer(url, None, Duration::from_secs(1), Some(token))
                .await
                .is_err()
        );
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(tcp)
            .await
            .unwrap();
        let request = String::from_utf8(support::request(&mut tls).await).unwrap();
        assert!(request.contains("\r\nAuthorization: Bearer test-token\r\n"));
        assert!(request.starts_with("GET /metadata/1.1.1.1 HTTP/1.1\r\n"));
        tls.write_all(
            b"HTTP/1.1 302 Moved\r\nLocation: https://elsewhere.test/\r\nContent-Length: 0\r\n\r\n",
        )
        .await
        .unwrap();
        let _ = tls.shutdown().await;
    });
    let result = client
        .get_with_bearer(
            &format!("https://fixed.test:{port}/metadata/1.1.1.1"),
            Some("127.0.0.1".parse().unwrap()),
            Duration::from_secs(2),
            Some("test-token"),
        )
        .await;
    assert!(matches!(result, Err(tcp_bench_rs::Error::HttpStatus(302))));
    server.await.unwrap();
}

#[tokio::test]
async fn fixed_ip_preserves_sni_host_and_single_connection() {
    let (config, client) = tls_configs();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(tcp)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.server_name(), Some("fixed.test"));
        let mut request = Vec::new();
        loop {
            let byte = tls.read_u8().await.unwrap();
            request.push(byte);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(
            String::from_utf8(request)
                .unwrap()
                .contains(&format!("Host: fixed.test:{port}\r\n"))
        );
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n")
            .await
            .unwrap();
        for _ in 0..16 {
            if tls.write_all(&[0xab; 4096]).await.is_err() {
                break;
            }
        }
        let _ = tls.shutdown().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    });
    let transfer = throughput::download(
        &client,
        TransferConfig {
            url: &format!("https://fixed.test:{port}/data"),
            fixed_ip: Some("127.0.0.1".parse().unwrap()),
            max_bytes: 10001,
            duration: Duration::from_secs(2),
            setup_timeout: Duration::from_secs(2),
        },
        &Cancellation::default(),
    )
    .await
    .unwrap();
    assert_eq!(transfer.body_bytes, 10001);
    assert_eq!(transfer.stop_reason, "byte_limit");
    assert!(transfer.tls_ms.is_some());
    assert!(transfer.body_bits_per_second.unwrap() > 0.0);
    assert_eq!(transfer.tcp_after.remote_sender_retransmissions, None);
    server.await.unwrap();
}

#[tokio::test]
async fn wrong_hostname_and_untrusted_certificates_are_rejected() {
    for trusted in [false, true] {
        let (config, trusted_client) = tls_configs();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(stream)
                .await;
        });
        let client = if trusted {
            trusted_client
        } else {
            Client::default()
        };
        let hostname = if trusted { "wrong.test" } else { "fixed.test" };
        assert!(
            client
                .get(
                    &format!("https://{hostname}:{port}/"),
                    Some("127.0.0.1".parse().unwrap()),
                    Duration::from_secs(2)
                )
                .await
                .is_err()
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn stalled_body_obeys_duration_and_cancellation() {
    for cancellation in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            support::request(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let cancel = Cancellation::default();
        let copy = cancel.clone();
        let trigger = tokio::spawn(async move {
            if cancellation {
                tokio::time::sleep(Duration::from_millis(50)).await;
                copy.cancel();
            }
        });
        let transfer = throughput::download(
            &Client::default(),
            TransferConfig {
                url: &format!("http://127.0.0.1:{port}/"),
                fixed_ip: None,
                max_bytes: 1000,
                duration: Duration::from_millis(100),
                setup_timeout: Duration::from_secs(2),
            },
            &cancel,
        )
        .await
        .unwrap();
        assert_eq!(transfer.body_bytes, 3);
        assert_eq!(
            transfer.stop_reason,
            if cancellation {
                "cancelled"
            } else {
                "duration_limit"
            }
        );
        assert!(transfer.body_seconds < 1.0);
        trigger.await.unwrap();
        server.abort();
    }
}

#[tokio::test]
async fn body_errors_preserve_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        support::request(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc")
            .await
            .unwrap();
    });
    let transfer = throughput::download(
        &Client::default(),
        TransferConfig {
            url: &format!("http://127.0.0.1:{port}/"),
            fixed_ip: None,
            max_bytes: 1000,
            duration: Duration::from_secs(2),
            setup_timeout: Duration::from_secs(2),
        },
        &Cancellation::default(),
    )
    .await
    .unwrap();
    assert_eq!(transfer.body_bytes, 3);
    assert_eq!(transfer.stop_reason, "error");
    assert!(transfer.error.is_some());
    server.await.unwrap();
}
