"""Offline distribution tests. All downloads are fixtures, never public requests."""
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest

LAUNCHER = Path(__file__).resolve().parents[1] / "runTcpBench.sh"
ASSET = "tcp-bench-rs-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
PROGRAM = b'''#!/usr/bin/env python3
import json, os, signal, sys, time
if os.environ.get("FIXTURE_WAIT"):
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    with open(os.environ["FIXTURE_READY"], "w") as f: f.write(str(os.getpid()))
    while True: time.sleep(0.05)
print(json.dumps(sys.argv[1:]))
sys.exit(int(os.environ.get("FIXTURE_EXIT", "0")))
'''


@unittest.skipUnless(sys.platform.startswith("linux"), "GNU/Linux distribution tests")
class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="tcp-bench-launcher-test-")
        self.root = Path(self.directory.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                        TMPDIR=str(self.scratch), FIXTURE_ROOT=str(self.root),
                        TCP_BENCH_RS_VERSION="v0.1.0")
        self.script("uname", '#!/bin/bash\nif [[ "$1" == -s ]]; then echo Linux; else echo "${FIXTURE_ARCH:-x86_64}"; fi\n')
        self.script("getconf", '#!/bin/bash\necho "${FIXTURE_LIBC:-glibc 2.35}"\n')
        self.script("curl", '''#!/usr/bin/env python3
import os, pathlib, shutil, sys
args = sys.argv[1:]
root = pathlib.Path(os.environ["FIXTURE_ROOT"])
assert args[0] == "--disable"
assert args[args.index("--proto")+1] == "=https"
assert args[args.index("--proto-redir")+1] == "=https"
assert "--max-time" in args and "--max-filesize" in args
assert args[-1].startswith("https://github.com/giejqf/tcp-bench-rs/releases/download/v0.1.0/")
with (root / "requests").open("a") as f: f.write(args[-1] + "\\n")
if os.environ.get("FIXTURE_DOWNLOAD_FAIL"): sys.exit(22)
source = root / ("checksum" if args[-1].endswith(".sha256") else "archive")
shutil.copyfile(source, args[args.index("--output")+1])
''')
        self.archive()

    def tearDown(self):
        self.directory.cleanup()

    def script(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o700)

    def archive(self, extra=None, notices=True):
        with tarfile.open(self.root / "archive", "w:gz") as archive:
            def file(name, contents):
                info = tarfile.TarInfo(name)
                info.size = len(contents)
                info.mode = 0o700 if name == "tcp-bench-rs" else 0o600
                archive.addfile(info, io.BytesIO(contents))
            file("tcp-bench-rs", PROGRAM)
            if notices:
                file("LICENSE", b"test license")
                file("NOTICE", b"test notice")
                folder = tarfile.TarInfo("third-party/")
                folder.type = tarfile.DIRTYPE
                folder.mode = 0o700
                archive.addfile(folder)
            if isinstance(extra, str):
                file(extra, b"unsafe")
            elif extra:
                archive.addfile(extra)
        digest = hashlib.sha256((self.root / "archive").read_bytes()).hexdigest()
        (self.root / "checksum").write_text(f"{digest}  {ASSET}\n")

    def run_launcher(self, *args):
        result = subprocess.run(["bash", str(LAUNCHER), *args], env=self.env,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(list(self.scratch.iterdir()), [], "temporary files leaked")
        return result

    def test_default_help_and_exact_argument_forwarding(self):
        result = self.run_launcher()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), ["--help"])
        arguments = ["--target", "::1", "space value", "$(touch nope)", "'quoted'", ""]
        result = self.run_launcher(*arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), arguments)

    def test_child_exit_status_is_preserved(self):
        self.env["FIXTURE_EXIT"] = "1"
        self.assertEqual(self.run_launcher("--version").returncode, 1)

    def test_dependency_version_build_metadata_in_notices_is_allowed(self):
        self.archive(extra="third-party/wasi-0.11.1+wasi-snapshot-preview1/LICENSE")
        result = self.run_launcher("--help")
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(os.environ.get("TCP_BENCH_TEST_ARCHIVE"), "release package smoke test")
    def test_real_release_archive(self):
        archive = Path(os.environ["TCP_BENCH_TEST_ARCHIVE"])
        contents = archive.read_bytes()
        (self.root / "archive").write_bytes(contents)
        (self.root / "checksum").write_text(f"{hashlib.sha256(contents).hexdigest()}  {archive.name}\n")
        self.env["FIXTURE_ARCH"] = os.uname().machine
        result = self.run_launcher("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "tcp-bench-rs 0.1.0")

    def test_checksum_failure_does_not_execute(self):
        (self.root / "checksum").write_text(f"{'0' * 64}  {ASSET}\n")
        result = self.run_launcher()
        self.assertEqual(result.returncode, 2)
        self.assertIn("checksum mismatch", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_wrong_checksum_filename_is_rejected(self):
        (self.root / "checksum").write_text(f"{'0' * 64}  ../../elsewhere\n")
        result = self.run_launcher()
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid release checksum", result.stderr)

    def test_unsafe_paths_links_and_duplicate_binaries_are_rejected(self):
        link = tarfile.TarInfo("third-party/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/tmp"
        for extra in ["../escape", "/absolute", "third-party/../../escape", "tcp-bench-rs", link]:
            with self.subTest(extra=str(extra)):
                self.archive(extra=extra)
                result = self.run_launcher()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, "")

    def test_license_notices_are_required(self):
        self.archive(notices=False)
        result = self.run_launcher()
        self.assertEqual(result.returncode, 2)
        self.assertIn("license notices", result.stderr)

    def test_unsupported_platforms_and_invalid_versions_fail_before_download(self):
        for key, value in [("FIXTURE_ARCH", "riscv64"), ("FIXTURE_LIBC", "glibc 2.31"),
                           ("FIXTURE_LIBC", "musl"), ("TCP_BENCH_RS_VERSION", "../../bad")]:
            self.env[key] = value
            result = self.run_launcher()
            self.assertEqual(result.returncode, 2)
            self.assertFalse((self.root / "requests").exists())
            del self.env[key]

    def test_download_failure_is_explicit(self):
        self.env["FIXTURE_DOWNLOAD_FAIL"] = "1"
        result = self.run_launcher()
        self.assertEqual(result.returncode, 2)
        self.assertIn("download failed", result.stderr)

    def test_sigterm_reaches_child_and_cleans_up(self):
        ready = self.root / "ready"
        self.env.update(FIXTURE_WAIT="1", FIXTURE_READY=str(ready))
        process = subprocess.Popen(["bash", str(LAUNCHER), "--version"], env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists(), "child did not start")
            pid = int(ready.read_text())
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=5)
            self.assertEqual(process.returncode, 143)
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            self.assertEqual(list(self.scratch.iterdir()), [])
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()


if __name__ == "__main__":
    unittest.main()
