"""Volatility symbol tables found or made from a memory image's kernel banner
(rowanholt/memory/symbols): the banner parsed, each publisher's file and hash, the check before
anything is opened, the cache index, and the downloads switch. No network: each publisher's
answers are canned."""
import base64
import gzip
import hashlib
import io
import json
import lzma
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.append(str(REPO / "src" / "analysis"))

from rowanholt.memory.symbols import build, cache, resolve, sources  # noqa: E402
from rowanholt.memory.symbols.banner import parse  # noqa: E402

UBUNTU = ("Linux version 5.15.0-91-generic (buildd@lcy02-amd64-045) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, "
          "GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 (Ubuntu 5.15.0-91.101-generic 5.15.131)")
HWE = "Linux version 5.8.0-44-generic (buildd@lcy01-amd64-014) (gcc ...) #50~20.04.1-Ubuntu SMP Wed Feb 10 21:07:30 UTC 2021"
DEBIAN = ("Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, "
          "GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.76-1 (2024-02-01)")
ROCKY = ("Linux version 5.14.0-362.8.1.el9_3.x86_64 (mockbuild@iad1-prod-build001.bld.equ.rockylinux.org) "
         "(gcc (GCC) 11.4.1 20230605 (Red Hat 11.4.1-2)) #1 SMP PREEMPT_DYNAMIC Wed Nov 8 17:36:32 UTC 2023")
FEDORA = "Linux version 6.5.6-300.fc39.x86_64 (mockbuild@fedoraproject.org) (gcc ...) #1 SMP PREEMPT_DYNAMIC"
DARWIN = "Darwin Kernel Version 21.6.0: Mon Aug 22 20:17:10 PDT 2022; root:xnu-8020.140.49~2/RELEASE_X86_64"


def isf(banner):
    """A minimal ISF serving the banner, xz'd."""
    data = base64.b64encode((banner + "\n\x00").encode()).decode()
    return lzma.compress(json.dumps({"symbols": {"linux_banner": {"constant_data": data}}}).encode())


class Publisher:
    """Canned answers by URL; a test's fetch."""
    def __init__(self, pages):
        self.pages, self.asked = pages, []

    def __call__(self, url):
        self.asked.append(url)
        for prefix, body in self.pages.items():
            if url.startswith(prefix):
                return body if isinstance(body, bytes) else json.dumps(body).encode()
        raise sources.SourceError(f"404 {url}")


class Response(io.BytesIO):
    def __init__(self, body, url):
        super().__init__(body)
        self.url = url

    def geturl(self):
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def serving(files):
    """urlopen serving files by URL."""
    def urlopen(request, timeout=None):
        return Response(files[request.full_url], request.full_url)
    return mock.patch.object(build.urllib.request, "urlopen", urlopen)


class Banners(unittest.TestCase):
    def test_each_distribution(self):
        k = parse(UBUNTU)
        self.assertEqual((k.os, k.distro, k.release, k.package_version, k.arch),
                         ("linux", "ubuntu", "5.15.0-91-generic", "5.15.0-91.101", "x86_64"))
        self.assertEqual(parse(HWE).package_version, "5.8.0-44.50~20.04.1")
        self.assertEqual((parse(DEBIAN).distro, parse(DEBIAN).package_version), ("debian", "6.1.76-1"))
        k = parse(ROCKY)
        self.assertEqual((k.distro, k.package_version, k.point_release), ("rocky", "5.14.0-362.8.1.el9_3", "9.3"))
        self.assertEqual(parse(FEDORA).distro, "fedora")
        k = parse(DARWIN)
        self.assertEqual((k.os, k.release, k.package_version), ("mac", "21.6.0", "8020.140.49~2"))
        self.assertIsNone(parse("Windows 10"))

    def test_banners_from_memory_py_output(self):
        # memory.py keeps the repr of Volatility's stdout: literal \n and \t
        output = str(f"Volatility 3\n\nOffset\tBanner\n\n0x1000\t{UBUNTU}\n0x2000\t{UBUNTU}\n".encode())[2:-1]
        self.assertEqual(resolve.banners_from(output), [UBUNTU])


class Sources(unittest.TestCase):
    def test_prebuilt_by_exact_banner_with_release_digest(self):
        url = ("https://github.com/Abyss-W4tcher/volatility3-symbols/releases/download/"
               "isf-Ubuntu-amd64-5.15.0-91-generic/Ubuntu_5.15.0-91-generic_5.15.0-91.101_amd64.json.xz")
        get = Publisher({sources.GITHUB_RELEASE.split("{")[0]: {"assets": [
            {"name": url.rsplit("/", 1)[1], "digest": "sha256:ab12", "size": 9}]}})
        item = sources.prebuilt(parse(UBUNTU), get, index={UBUNTU + "\n\x00": [url]})
        self.assertEqual((item.url, item.algorithm, item.digest, item.kind), (url, "sha256", "ab12", "isf"))
        with self.assertRaises(sources.SourceError):
            sources.prebuilt(parse(DEBIAN), get, index={UBUNTU: [url]})

    def test_prebuilt_without_a_digest_is_refused(self):
        url = "https://github.com/x/y/releases/download/tag/file.json.xz"
        get = Publisher({sources.GITHUB_RELEASE.split("{")[0]: {"assets": [{"name": "file.json.xz"}]}})
        with self.assertRaisesRegex(sources.SourceError, "no published SHA-256"):
            sources.prebuilt(parse(UBUNTU), get, index={UBUNTU: [url]})

    def test_ubuntu_from_launchpad(self):
        ddeb = "https://launchpad.net/ubuntu/+archive/primary/+files/linux-image-unsigned-5.15.0-91-generic-dbgsym_5.15.0-91.101_amd64.ddeb"
        get = Publisher({
            "https://api.launchpad.net/1.0/": {"entries": [{
                "self_link": "https://api.launchpad.net/1.0/ubuntu/+archive/primary/+binarypub/123",
                "distro_arch_series_link": "https://api.launchpad.net/1.0/ubuntu/jammy/amd64", "status": "Published"}]},
            "https://api.launchpad.net/devel/": [{"url": ddeb, "sha256": "cd34", "size": 1057913640}],
        })
        item = sources.debug_package(parse(UBUNTU), get)
        self.assertEqual((item.url, item.digest, item.kind, item.size), (ddeb, "cd34", "deb", 1057913640))
        self.assertIn("version=5.15.0-91.101", get.asked[0])
        self.assertIn("/+binarypub/123?", get.asked[1])

    def test_debian_from_snapshot_by_sha1(self):
        get = Publisher({"https://snapshot.debian.org/mr/": {"result": [
            {"architecture": "arm64", "hash": "aaa"}, {"architecture": "amd64", "hash": "bbb"}]}})
        item = sources.debug_package(parse(DEBIAN), get)
        self.assertEqual((item.url, item.algorithm, item.digest), ("https://snapshot.debian.org/file/bbb", "sha1", "bbb"))
        self.assertIn("linux-image-6.1.0-18-amd64-dbg/6.1.76-1/", get.asked[0])

    def test_rocky_from_the_vault_by_repository_sha256(self):
        base = "https://dl.rockylinux.org/vault/rocky/9.3/BaseOS/x86_64/debug/tree/"
        repomd = (b'<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary">'
                  b'<location href="repodata/x-primary.xml.gz"/></data></repomd>')
        primary = gzip.compress(
            b'<metadata xmlns="http://linux.duke.edu/metadata/common"><package>'
            b'<checksum type="sha256">ef56</checksum><size package="900"/>'
            b'<location href="Packages/k/kernel-debuginfo-5.14.0-362.8.1.el9_3.x86_64.rpm"/></package></metadata>')
        get = Publisher({base + "repodata/repomd.xml": repomd, base + "repodata/x-primary.xml.gz": primary})
        item = sources.debug_package(parse(ROCKY), get)
        self.assertEqual(item.url, base + "Packages/k/kernel-debuginfo-5.14.0-362.8.1.el9_3.x86_64.rpm")
        self.assertEqual((item.digest, item.kind, item.size), ("ef56", "rpm", 900))

    def test_fedora_and_macos_say_why_not(self):
        with self.assertRaisesRegex(sources.SourceError, "no file hash"):
            sources.debug_package(parse(FEDORA))
        with self.assertRaisesRegex(sources.SourceError, "Apple ID"):
            sources.debug_package(parse(DARWIN))

    def test_only_https(self):
        with self.assertRaises(sources.SourceError):
            sources.fetch("http://example.org/")


class Downloads(unittest.TestCase):
    def test_a_file_that_fails_its_hash_is_deleted(self):
        body = b"not the table"
        item = sources.Download("https://h/x.json.xz", "sha256", "00" * 32, "isf", "prebuilt", name="x.json.xz")
        with tempfile.TemporaryDirectory() as tmp, serving({item.url: body}):
            with self.assertRaisesRegex(build.BuildError, "is not the published"):
                build.download(item, Path(tmp))
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_a_redirect_off_https_is_refused(self):
        item = sources.Download("https://h/x", "sha1", "00", "deb", "debian", name="x")

        def urlopen(request, timeout=None):
            return Response(b"", "http://h/x")
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(build.urllib.request, "urlopen", urlopen):
            with self.assertRaises(sources.SourceError):
                build.download(item, Path(tmp))


class Resolving(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "linux").mkdir()
        self.audit = []

    def tearDown(self):
        self.tmp.cleanup()

    def resolve(self, banner, **kwargs):
        return resolve.resolve(banner, self.audit.append, self.root, **kwargs)

    def test_a_table_already_there_is_indexed_once(self):
        (self.root / "linux" / "mine.json.xz").write_bytes(isf(UBUNTU))
        first = self.resolve(UBUNTU, allow_downloads=False)
        self.assertEqual((first.status, first.table.name), ("local", "mine.json.xz"))
        self.assertEqual(self.resolve(UBUNTU, allow_downloads=False).status, "cached")
        self.assertTrue((self.root / "linux" / cache.INDEX).is_file())
        self.assertEqual(self.audit, [])

    def test_downloads_off_names_the_command(self):
        result = self.resolve(UBUNTU, allow_downloads=False)
        self.assertEqual(result.status, "offline")
        self.assertIn("rowanholt symbols fetch --banner 'Linux version 5.15.0-91-generic", result.message)
        self.assertEqual(self.audit, [])

    def test_the_switch(self):
        with mock.patch.dict(os.environ, {"ROWANHOLT_SYMBOL_DOWNLOADS": "off"}):
            self.assertFalse(resolve.downloads_enabled())
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertTrue(resolve.downloads_enabled())

    def test_prebuilt_fetched_checked_indexed_and_audited(self):
        table = isf(UBUNTU)
        item = sources.Download("https://h/u.json.xz", "sha256", hashlib.sha256(table).hexdigest(), "isf", "prebuilt",
                                name="u.json.xz")
        with mock.patch.object(sources, "prebuilt", return_value=item), serving({item.url: table}):
            result = self.resolve(UBUNTU, allow_downloads=True)
        self.assertEqual(result.status, "fetched")
        self.assertEqual(result.table, self.root / "linux" / "ubuntu-5.15.0-91-generic-x86_64.json.xz")
        entry = cache.find("linux", UBUNTU, self.root)
        self.assertEqual((entry["source"], entry["url"], entry["sha256"]), ("prebuilt", item.url, hashlib.sha256(table).hexdigest()))
        self.assertTrue(self.audit[0].startswith("symbols download https://h/u.json.xz (sha256 "))
        self.assertIn("symbols fetched", self.audit[-1])

    def test_a_bad_download_falls_through_and_leaves_nothing(self):
        item = sources.Download("https://h/u.json.xz", "sha256", "00" * 32, "isf", "prebuilt", name="u.json.xz")
        with mock.patch.object(sources, "prebuilt", return_value=item), \
                mock.patch.object(sources, "debug_package", side_effect=sources.SourceError("nothing")), \
                serving({item.url: b"tampered"}):
            result = self.resolve(UBUNTU, allow_downloads=True)
        self.assertEqual(result.status, "unavailable")
        self.assertIn("is not the published", result.message)
        self.assertEqual(list((self.root / "linux").glob("*.json*")), [])
        self.assertIn("symbols failed", self.audit[-1])
        self.assertIn("symbols failed", (self.root / "linux" / cache.LOG).read_text())

    def test_building_needs_dwarf2json(self):
        item = sources.Download("https://h/k.ddeb", "sha256", "00", "deb", "ubuntu", name="k.ddeb")
        with mock.patch.object(sources, "prebuilt", side_effect=sources.SourceError("not in the prebuilt collection")), \
                mock.patch.object(sources, "debug_package", return_value=item), \
                mock.patch.object(resolve.shutil, "which", return_value=None):
            result = self.resolve(UBUNTU, allow_downloads=True)
        self.assertEqual(result.status, "unavailable")
        self.assertIn("dwarf2json isn't installed", result.message)
        self.assertIn("rowanholt symbols add --vmlinux", result.message)

    def test_macos_points_at_its_kdk(self):
        (self.root / "mac").mkdir()
        with mock.patch.object(sources, "prebuilt", side_effect=sources.SourceError("not in the prebuilt collection")):
            result = self.resolve(DARWIN, allow_downloads=True)
        self.assertIn("Kernel Debug Kit for xnu-8020.140.49~2", result.message)


class InTheMemoryStep(unittest.TestCase):
    def test_no_table_skips_the_image_and_says_why(self):
        from rowanholt.memory import memory

        output = str(f"Offset\tBanner\n0x1\t{UBUNTU}\n".encode())[2:-1]
        with tempfile.TemporaryDirectory() as case, tempfile.TemporaryDirectory() as root, \
                mock.patch.dict(os.environ, {"ROWANHOLT_SYMBOLS_DIR": root, "ROWANHOLT_SYMBOL_DOWNLOADS": "off"}), \
                mock.patch.dict(memory.KERNEL_BANNERS, {"/e/mem.lime": output}):
            self.assertFalse(memory.ensure_symbols(case, "", "/e/mem.lime"))
            log = Path(case, "rowanholt_audit.log").read_text()
        self.assertIn(",symbols,mem.lime,", log)
        self.assertIn("rowanholt symbols fetch --banner", log)

    def test_a_windows_image_is_left_to_volatility(self):
        from rowanholt.memory import memory

        with tempfile.TemporaryDirectory() as case:
            self.assertTrue(memory.ensure_symbols(case, "", "/e/win.raw"))


class TheCommand(unittest.TestCase):
    def test_banner_from_a_vmlinux(self):
        from rowanholt.memory.symbols import __main__ as cli

        with tempfile.TemporaryDirectory() as tmp:
            vmlinux = Path(tmp, "vmlinux")
            vmlinux.write_bytes(b"\x7fELF" + b"\0" * 64 + UBUNTU.encode() + b"\n\0rest")
            self.assertEqual(cli._banner_in(vmlinux), UBUNTU)

    def test_add_a_table_indexes_it(self):
        from rowanholt.memory.symbols import __main__ as cli

        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"ROWANHOLT_SYMBOLS_DIR": root}):
            table = Path(tmp, "mine.json.xz")
            table.write_bytes(isf(DEBIAN))
            self.assertEqual(cli.main(["add", "--table", str(table)]), 0)
            self.assertEqual(cache.find("linux", DEBIAN, Path(root))["source"], "added")
            self.assertIn("symbols added mine.json.xz", Path(root, "linux", cache.LOG).read_text())


if __name__ == "__main__":
    unittest.main()
