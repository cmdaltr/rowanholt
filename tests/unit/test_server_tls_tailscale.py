"""server init --tls tailscale and server cert: a MagicDNS-named server serves Tailscale's certificate as
files, since Caddy hands *.ts.net names to a Tailscale daemon its container can't reach (no certificate,
TLS alert 80: found standing up the team server on a tailnet, 5 November 2026). Run against a copy of
scripts/server in a temporary tree, with stand-ins for tailscale, sudo and docker on PATH."""
import os
import shutil
import stat
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NAME = "rowanholt.tail1234.ts.net"


def tree(tmp_path: Path) -> tuple:
    root = tmp_path / "rowanholt"
    (root / "scripts" / "server").mkdir(parents=True)
    (root / "deploy" / "linux").mkdir(parents=True)
    # server init is deploy/linux/install.sh; it runs scripts/server/server-cert.sh for the certificate
    shutil.copy(REPO / "deploy" / "linux" / "install.sh", root / "deploy" / "linux" / "install.sh")
    shutil.copy(REPO / "scripts" / "server" / "server-cert.sh", root / "scripts" / "server" / "server-cert.sh")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "90", "-subj", f"/CN={NAME}",
                    "-keyout", str(tmp_path / "issued.key"), "-out", str(tmp_path / "issued.crt")],
                   check=True, capture_output=True)
    stand_ins = {
        # tailscale cert --cert-file C --key-file K NAME: hands over the "issued" pair; serve is logged,
        # and refused while TS_REFUSE is set (an untagged device, say)
        "tailscale": (f'[ "$1" = cert ] || {{ echo "$*" >> "{tmp_path}/tailscale.log"; '
                      '[ -z "$TS_REFUSE" ] || { echo "$TS_REFUSE" >&2; exit 1; }; exit 0; }\n'
                      f'cp "{tmp_path}/issued.crt" "$3"\ncp "{tmp_path}/issued.key" "$5"\n'),
        "sudo": 'exec "$@"\n',
        "docker": "exit 1\n",
    }
    for name, body in stand_ins.items():
        (bin_dir / name).write_text("#!/bin/sh\n" + body)
        (bin_dir / name).chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:/usr/bin:/bin:/usr/sbin"}  # macOS keeps chown in /usr/sbin
    return root, env


def run(root: Path, env: dict, *args: str) -> subprocess.CompletedProcess:
    script = root / "deploy" / "linux" / "install.sh" if args[0] == "init" else root / "scripts" / "server" / "server-cert.sh"
    return subprocess.run(["bash", str(script), *args[1:]], env=env,
                          capture_output=True, text=True)


def setting(root: Path, key: str) -> str:
    lines = [line for line in (root / ".env").read_text().splitlines() if line.startswith(f"{key}=")]
    return lines[-1].split("=", 1)[1] if lines else ""


def test_tailscale_certificate_served_as_files(tmp_path):
    root, env = tree(tmp_path)
    done = run(root, env, "init", NAME, "--tls", "tailscale")
    assert done.returncode == 0, done.stderr
    assert setting(root, "ROWANHOLT_TLS") == "/certs/rowanholt.crt /certs/rowanholt.key"
    assert setting(root, "ROWANHOLT_TLS_SOURCE") == "tailscale"
    certs = root / "deploy" / "server" / "certs"
    assert (certs / "rowanholt.crt").read_bytes() == (tmp_path / "issued.crt").read_bytes()
    assert stat.S_IMODE((certs / "rowanholt.key").stat().st_mode) == 0o600
    assert "Tailscale's" in done.stdout and "rowanholt server cert" in done.stdout

    again = run(root, env, "cert")
    assert again.returncode == 0 and "unchanged" in again.stdout, again.stderr


def test_ts_net_name_refused_without_tailscale_or_files(tmp_path):
    root, env = tree(tmp_path)
    for tls in ("internal", "admin@example.org"):
        done = run(root, env, "init", NAME, "--tls", tls)
        assert done.returncode == 1 and "--tls tailscale" in done.stderr, (tls, done.stderr)


def test_tailscale_mode_needs_a_ts_net_name(tmp_path):
    root, env = tree(tmp_path)
    done = run(root, env, "init", "rowanholt.dfir.example.org", "--tls", "tailscale")
    assert done.returncode == 1 and "MagicDNS" in done.stderr


def test_https_port_moves_rowanholt_off_443_and_is_kept(tmp_path):
    # The homelab server's front door (homelab-proxy) holds 80 and 443; Rowanholt moves aside
    root, env = tree(tmp_path)
    assert run(root, env, "init", NAME, "--tls", "tailscale").returncode == 0
    assert (setting(root, "ROWANHOLT_HTTPS_PORT"), setting(root, "ROWANHOLT_HTTP_PUBLISH"),
            setting(root, "ROWANHOLT_PUBLIC_URL")) == ("443", "80", f"https://{NAME}")
    secret_key = setting(root, "SECRET_KEY")

    done = run(root, env, "init", NAME, "--tls", "tailscale", "--https-port", "8443")
    assert done.returncode == 0, done.stderr
    assert (setting(root, "ROWANHOLT_HTTPS_PORT"), setting(root, "ROWANHOLT_HTTP_PUBLISH"),
            setting(root, "ROWANHOLT_PUBLIC_URL")) == ("8443", "127.0.0.1:8080", f"https://{NAME}:8443")
    assert setting(root, "SECRET_KEY") == secret_key and "First admin" not in done.stdout

    # init again without the option keeps the port
    assert run(root, env, "init", NAME, "--tls", "tailscale").returncode == 0
    assert setting(root, "ROWANHOLT_PUBLIC_URL") == f"https://{NAME}:8443"
    for bad in ("80", "5601", "http"):
        assert run(root, env, "init", NAME, "--tls", "tailscale", "--https-port", bad).returncode == 1


def test_cert_refused_on_a_server_not_using_tailscale(tmp_path):
    root, env = tree(tmp_path)
    assert run(root, env, "init", "rowanholt.dfir.example.org").returncode == 0
    done = run(root, env, "cert")
    assert done.returncode == 1 and "isn't Tailscale's" in done.stderr


def served(tmp_path: Path) -> list:
    log = tmp_path / "tailscale.log"
    lines = log.read_text().splitlines() if log.exists() else []
    log.unlink(missing_ok=True)
    return lines


def test_service_name_becomes_the_public_url(tmp_path):
    # homelab: Rowanholt at https://rowanholt.<tailnet>.ts.net, beside homelab.<tailnet>.ts.net:8443
    root, env = tree(tmp_path)
    server = "homelab.tail1234.ts.net"
    done = run(root, env, "init", server, "--tls", "tailscale", "--https-port", "8443", "--service", "rowanholt")
    assert done.returncode == 0, done.stderr
    assert (setting(root, "ROWANHOLT_SERVICE"), setting(root, "ROWANHOLT_PUBLIC_URL"),
            setting(root, "ROWANHOLT_OTHER_URLS")) == ("rowanholt", "https://rowanholt.tail1234.ts.net",
                                                        f"https://{server}:8443")
    assert served(tmp_path) == [
        "serve --service=svc:rowanholt --https=443 http://127.0.0.1:5680",
        "serve --service=svc:rowanholt --https=7755 http://127.0.0.1:5681",
        "serve --service=svc:rowanholt --https=5601 http://127.0.0.1:5682",
        "serve --service=svc:rowanholt --https=5602 http://127.0.0.1:5683",
    ]
    assert setting(root, "ROWANHOLT_HOSTNAME") == server  # its certificate and ports are unchanged

    # kept on the next init, and served again
    assert run(root, env, "init", server, "--tls", "tailscale").returncode == 0
    assert setting(root, "ROWANHOLT_PUBLIC_URL") == "https://rowanholt.tail1234.ts.net"
    assert len(served(tmp_path)) == 4

    done = run(root, env, "init", server, "--tls", "tailscale", "--service", "off")
    assert done.returncode == 0, done.stderr
    assert (setting(root, "ROWANHOLT_SERVICE"), setting(root, "ROWANHOLT_PUBLIC_URL"),
            setting(root, "ROWANHOLT_OTHER_URLS")) == ("", f"https://{server}:8443", "")
    assert served(tmp_path) == ["serve drain svc:rowanholt", "serve clear svc:rowanholt"]


def test_service_refused_changes_nothing(tmp_path):
    root, env = tree(tmp_path)
    server = "homelab.tail1234.ts.net"
    assert run(root, env, "init", server, "--tls", "tailscale").returncode == 0
    done = run(root, {**env, "TS_REFUSE": "service hosts must be tagged nodes"},
               "init", server, "--tls", "tailscale", "--service", "rowanholt")
    assert done.returncode == 1 and "tagged" in done.stderr
    assert (setting(root, "ROWANHOLT_SERVICE"), setting(root, "ROWANHOLT_PUBLIC_URL")) == ("", f"https://{server}")


def test_service_needs_tailscale_and_a_label_of_its_own(tmp_path):
    root, env = tree(tmp_path)
    done = run(root, env, "init", "rowanholt.dfir.example.org", "--service", "rowanholt")
    assert done.returncode == 1 and "--tls tailscale" in done.stderr
    for bad in ("Rowanholt", "-x", "a.b", "rowanholt"):  # rowanholt: the server's own name
        done = run(root, env, "init", NAME, "--tls", "tailscale", "--service", bad)
        assert done.returncode == 1, bad
    assert not served(tmp_path)
