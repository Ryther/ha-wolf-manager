#!/usr/bin/env python3
"""Exercise installed distro SSH/sudo/systemd syntax with disposable test keys only."""
from __future__ import annotations

import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import time

FAMILY = sys.argv[1]
BASE = Path("/root/wolf-platform")
BASE.mkdir(mode=0o700)
TEMPLATES = Path("/templates")
RESULTS: dict[str, object] = {"scope": "container-only; SSH transport and policy, offline unit syntax; no real OS/GPU/Wolf streaming"}


def run(*args: str, success: bool = True, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if success and result.returncode:
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {(result.stdout + result.stderr)[-1500:]}")
    return result


def copy_template(source: str, destination: str, mode: int) -> None:
    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    shutil.copyfile(TEMPLATES / source, path)
    path.chmod(mode)


assert os.geteuid() == 0, "requires disposable root container"
run("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/bin/sh", "--password", "!", "wolf-manager")
account = pwd.getpwnam("wolf-manager")
assert account.pw_uid != 0 and account.pw_dir == "/nonexistent" and account.pw_shell == "/bin/sh"
assert not any("wolf-manager" in group.gr_mem and group.gr_gid != account.pw_gid for group in grp.getgrall())
shadow_password = next(line.split(":")[1] for line in Path("/etc/shadow").read_text().splitlines() if line.startswith("wolf-manager:"))
assert shadow_password.startswith(("!", "*"))
RESULTS["account_restriction"] = True

for source, destination, mode in [
    ("ssh-dispatcher", "/usr/libexec/wolf-manager/ssh-dispatcher", 0o755),
    ("wolf-host-root", "/usr/libexec/wolf-manager/wolf-host-root", 0o755),
    ("wolf-manager.sudoers", "/etc/sudoers.d/wolf-manager", 0o440),
]:
    copy_template(source, destination, mode)

# A fixed fake host executable proves OS transport/privilege policies, not native RPC.
# The Rust dispatcher and root helper have their own independent contract tests.
host = Path("/usr/local/bin/wolf-manager-host")
host.parent.mkdir(parents=True, exist_ok=True)
host.write_text('''#!/bin/sh
[ "$#" -eq 1 ] || exit 64
case "$1" in
 dispatch-rpc)
  [ "${BASH_ENV-unset}:${ENV-unset}:${LD_PRELOAD-unset}" = "unset:unset:unset" ] || exit 78
  [ "${SSH_ORIGINAL_COMMAND-}" = "wolf-manager-rpc-v1" ] || exit 64
  printf 'restricted-dispatch:%s\\n' "$(/usr/bin/id -u)"
  ;;
 privileged-rpc)
  [ "$(/usr/bin/id -u)" -eq 0 ] || exit 77
  printf 'fixed-root-helper\\n'
  ;;
 *) exit 64 ;;
esac
''')
host.chmod(0o755)

visudo = shutil.which("visudo")
assert visudo
run(visudo, "-c", "-f", "/etc/sudoers.d/wolf-manager")
assert "NOSETENV" in Path("/etc/sudoers.d/wolf-manager").read_text()
sudo = shutil.which("sudo")
assert sudo
allowed = run(sudo, "-u", "wolf-manager", sudo, "-n", "/usr/libexec/wolf-manager/wolf-host-root")
assert allowed.stdout.strip() == "fixed-root-helper"
assert run(sudo, "-u", "wolf-manager", sudo, "-n", "/usr/libexec/wolf-manager/wolf-host-root", "arbitrary", success=False).returncode != 0
assert run(sudo, "-u", "wolf-manager", sudo, "-n", "/bin/sh", "-c", "id", success=False).returncode != 0
RESULTS["sudo_exact_no_arguments"] = True

run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(BASE / "server"))
run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(BASE / "client"))
public = (BASE / "client.pub").read_text().strip()
authorized = Path("/etc/ssh/authorized_keys.d/wolf-manager")
authorized.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
authorized.write_text('restrict,command="/usr/libexec/wolf-manager/ssh-dispatcher" ' + public + "\n")
authorized.chmod(0o644)
assert authorized.stat().st_uid == 0
run(sudo, "-u", "wolf-manager", "/usr/bin/test", "-r", str(authorized))
assert run(sudo, "-u", "wolf-manager", "/usr/bin/test", "-w", str(authorized), success=False).returncode != 0
RESULTS["public_key_target_uid_readable_root_nonwritable"] = True

Path("/run/sshd").mkdir(parents=True, exist_ok=True, mode=0o755)
config = BASE / "sshd_config"
config.write_text(f'''Port 22222
ListenAddress 127.0.0.1
PidFile {BASE}/sshd.pid
HostKey {BASE}/server
UsePAM yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
LogLevel VERBOSE
AcceptEnv *
PermitUserEnvironment yes
AuthorizedKeysCommand /bin/false
AuthorizedKeysCommandUser root
TrustedUserCAKeys {BASE}/server.pub
AuthorizedPrincipalsCommand /bin/false
AuthorizedPrincipalsCommandUser root
AuthorizedPrincipalsFile {BASE}/client.pub
''' + (TEMPLATES / "90-wolf-manager.conf").read_text())
sshd = shutil.which("sshd")
assert sshd
run(sshd, "-t", "-f", str(config))
effective_result = run(sshd, "-T", "-f", str(config), "-C", "user=wolf-manager,host=localhost,addr=127.0.0.1")
effective = effective_result.stdout
if not effective:
    raise RuntimeError(f"empty sshd effective stdout, stderr={effective_result.stderr[:2500]!r}")
# OpenSSH releases differ in emitted keyword casing; preserve value casing.
effective_lines = [key.lower() + " " + value for line in effective.splitlines() for key, separator, value in [line.partition(" ")] if separator]
for expected in ["authenticationmethods publickey", "authorizedkeyscommand none", "trustedusercakeys none", "authorizedprincipalscommand none", "authorizedprincipalsfile none", "passwordauthentication no", "kbdinteractiveauthentication no", "permittty no", "disableforwarding yes", "permituserrc no", "forcecommand /usr/libexec/wolf-manager/ssh-dispatcher", "authorizedkeysfile /etc/ssh/authorized_keys.d/wolf-manager"]:
    assert expected in effective_lines, expected
assert [line for line in effective_lines if line.startswith("acceptenv ")] == ["acceptenv WOLF_MANAGER_UNUSED_ENV"]
assert not any(line.startswith("setenv ") and line != "setenv none" for line in effective_lines)
assert "permituserenvironment yes" in effective_lines
assert not Path("/nonexistent/.ssh").exists()
assert 'environment=' not in authorized.read_text()
RESULTS["global_client_environment_override_bounded"] = True
RESULTS["inherited_alternate_key_authority_disabled"] = True
RESULTS["user_environment_inputs_unavailable_without_global_changes"] = True
RESULTS["sshd_effective_match_policy"] = True

known = BASE / "known_hosts"
known.write_text("[127.0.0.1]:22222 " + (BASE / "server.pub").read_text())
ssh_command = ["ssh", "-i", str(BASE / "client"), "-p", "22222", "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}", "-o", "ConnectTimeout=5", "wolf-manager@127.0.0.1"]
log = (BASE / "sshd.log").open("w")
server = subprocess.Popen([sshd, "-D", "-e", "-f", str(config)], stdout=log, stderr=log)
try:
    for _ in range(100):
        try:
            with socket.create_connection(("127.0.0.1", 22222), timeout=0.1):
                break
        except OSError:
            if server.poll() is not None:
                raise RuntimeError((BASE / "sshd.log").read_text()[-1500:])
            time.sleep(0.05)
    accepted = run(*ssh_command, "wolf-manager-rpc-v1")
    assert accepted.stdout.strip() == f"restricted-dispatch:{account.pw_uid}"
    injected = run(*ssh_command[:-1], "-o", "SetEnv=BASH_ENV=/tmp/wolf-injected ENV=/tmp/wolf-injected LD_PRELOAD=/tmp/wolf-injected", ssh_command[-1], "wolf-manager-rpc-v1")
    assert injected.stdout.strip() == f"restricted-dispatch:{account.pw_uid}"
    RESULTS["client_shell_loader_environment_rejected"] = True
    wrong = run(*ssh_command, "id", success=False)
    assert wrong.returncode != 0 and not wrong.stdout
    forwarded = run(*ssh_command[:-1], "-W", "127.0.0.1:22222", ssh_command[-1], success=False, timeout=10)
    assert forwarded.returncode != 0
    RESULTS["real_ssh_allowed_command_only_no_forwarding"] = True
finally:
    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=5)
    log.close()

# Offline verification is deliberately separate from PID1/systemd service execution.
units = Path("/etc/systemd/system")
units.mkdir(parents=True, exist_ok=True)
copy_template("wolf.service", "/etc/systemd/system/wolf.service", 0o644)
(units / "wolf.service").write_text((units / "wolf.service").read_text().replace("@START_TIMEOUT@", "485"))
(units / "docker.service").write_text("[Unit]\nDescription=Disposable Docker dependency fixture\n[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n")
(Path("/tmp/wolf-catalog")).mkdir(mode=0o700)
catalog = (TEMPLATES / "wolf-manager-catalog.service").read_text().replace("@STEAM_UID@", str(account.pw_uid)).replace("@STEAM_GID@", str(account.pw_gid)).replace("@CATALOG_STATE@", '"/tmp/wolf-catalog"')
(units / "wolf-manager-catalog.service").write_text(catalog)
run("systemd-analyze", "verify", "/etc/systemd/system/wolf.service", "/etc/systemd/system/wolf-manager-catalog.service")
RESULTS["offline_systemd_unit_syntax"] = True
RESULTS["systemd_pid1_or_real_streaming_tested"] = False
RESULTS["native_rpc_tested_by_this_fixture"] = False
RESULTS["package_versions"] = {
    "openssh": (run("ssh", "-V").stdout + run("ssh", "-V").stderr).strip(),
    "sudo": run(sudo, "-V").stdout.splitlines()[0],
    "systemd": run("systemd-analyze", "--version").stdout.splitlines()[0],
}
RESULTS["os_release"] = Path("/etc/os-release").read_text()
print(json.dumps(RESULTS, sort_keys=True))
