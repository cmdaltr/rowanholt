"""Encrypted Gandalf archives: gandalf.py's Fernet .zip.enc and gandalf.sh's openssl .tar.gz.enc,
decrypted by Elrond with the <host>.shadowfax.key saved beside them (E24, G12).

Run: python3 -m unittest tests/unit/test_gandalf_encryption.py
"""
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Appended, not prepended: src/analysis/platform would shadow the stdlib module.
sys.path.append(str(ROOT / "src" / "analysis"))

from dernvale.core import gandalf  # noqa: E402

try:
    from cryptography.fernet import Fernet
except ImportError:  # the worker has it; a bare host may not
    Fernet = None

TEMPLATE = ROOT / "src" / "acquisition" / "python" / "collect_artefacts-py"


def zip_bytes(host):
    buf = io.BytesIO()
    # A fixed time: two calls a second apart would otherwise differ (the test compares bytes)
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo(f"{host}/artefacts/host.info", (2026, 1, 1, 0, 0, 0)), f"{host}::Linux\n")
        z.writestr(zipfile.ZipInfo(f"{host}/artefacts/etc+passwd", (2026, 1, 1, 0, 0, 0)), "root:x:0:0")
    return buf.getvalue()


class EncryptedArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.acq = root / "acquisitions"
        self.out = root / "out"
        self.acq.mkdir()
        self.out.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def assess(self):
        allimgs = {}
        gandalf.assess_gandalf(False, True, False, False, False, False, {}, str(self.acq) + "/", os.getcwd(),
                               False, [], str(self.out) + "/", "", allimgs, {}, "", False, False)
        return allimgs

    @unittest.skipIf(Fernet is None, "cryptography isn't installed")
    def test_fernet_zip_with_its_key_is_decrypted_and_ingested(self):
        key = Fernet.generate_key()
        (self.acq / "lab-ubuntu.zip.enc").write_bytes(Fernet(key).encrypt(zip_bytes("lab-ubuntu")))
        (self.acq / "lab-ubuntu.shadowfax.key").write_bytes(key + b"\n")
        self.assertEqual(list(self.assess().values()), ["lab-ubuntu::Linux"])
        self.assertFalse((self.out / gandalf.STAGING_DIR).exists())

    @unittest.skipIf(Fernet is None, "cryptography isn't installed")
    def test_wrong_key_is_reported_not_fatal(self):
        (self.acq / "lab-ubuntu.zip.enc").write_bytes(Fernet(Fernet.generate_key()).encrypt(zip_bytes("lab-ubuntu")))
        (self.acq / "lab-ubuntu.shadowfax.key").write_bytes(Fernet.generate_key())
        self.assertEqual(self.assess(), {})

    def test_no_key_says_how_to_decrypt(self):
        (self.acq / "lab-ubuntu.zip.enc").write_bytes(b"gAAAA-not-really")
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(self.assess(), {})
        self.assertIn("passkey_decrypt.py", buf.getvalue())

    @unittest.skipIf(not shutil.which("openssl"), "openssl isn't installed")
    def test_gandalf_sh_tarball_with_its_key(self):
        tar_path = Path(self.tmp.name) / "lab-rocky.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            for name, body in (("artefacts/host.info", "lab-rocky::Linux\n"), ("artefacts/etc+passwd", "root:x")):
                info = tarfile.TarInfo(name)
                info.size = len(body)
                tar.addfile(info, io.BytesIO(body.encode()))
        key = self.acq / "lab-rocky.shadowfax.key"
        key.write_text("c2hhZG93ZmF4IGlzIHRoZSBsb3JkIG9mIGFsbCBob3JzZXM=\n")
        subprocess.run(["openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-in", str(tar_path),
                        "-out", str(self.acq / "lab-rocky.tar.gz.enc"), "-pass", f"file:{key}"], check=True)
        self.assertEqual(list(self.assess().values()), ["lab-rocky::Linux"])


@unittest.skipIf(Fernet is None, "cryptography isn't installed")
class CollectorEncryptionTests(unittest.TestCase):
    def test_template_encrypts_with_the_key_and_drops_the_plaintext(self):
        # G12: gandalf.py writes the key into the script ({!r} of bytes), and the template
        # builds the Fernet itself
        ns = {}
        exec(compile(TEMPLATE.read_text(), str(TEMPLATE), "exec"), ns)
        key = Fernet.generate_key()
        literal = "{!r}".format(key)
        self.assertEqual(eval(literal), key)
        with tempfile.TemporaryDirectory() as tmp:
            host = os.path.join(tmp, "lab-ubuntu")
            Path(host + ".zip").write_bytes(zip_bytes("lab-ubuntu"))
            ns["encrypt_archive"](eval(literal), host)
            self.assertFalse(os.path.exists(host + ".zip"))
            self.assertEqual(Fernet(key).decrypt(Path(host + ".zip.enc").read_bytes()), zip_bytes("lab-ubuntu"))


if __name__ == "__main__":
    unittest.main()
