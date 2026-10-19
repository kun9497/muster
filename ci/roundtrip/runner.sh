#!/bin/sh
# runner.sh seeds the GitHub runner VM for the fix-roundtrip host row
# (3D-2c §5). It is idempotent: it removes every file a review script wrote,
# puts back the stock modes the repair run tightened, then applies every seed
# again, so the failure run plans every seeded block (S-18).
set -eu
export DEBIAN_FRONTEND=noninteractive
if ! command -v auditctl >/dev/null 2>&1 || ! dpkg -s libpam-pwquality >/dev/null 2>&1; then apt-get update -q && apt-get install -y -q auditd libpam-pwquality; fi
rm -f /etc/sysctl.d/99-muster-*.conf /etc/modprobe.d/99-muster-*.conf \
  /etc/ssh/sshd_config.d/00-muster-session.conf /etc/security/pwquality.conf.d/99-muster.conf
for kv in kernel.randomize_va_space=0 net.ipv4.icmp_echo_ignore_broadcasts=0 net.ipv4.conf.default.accept_redirects=1 \
  net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 net.ipv6.conf.default.accept_redirects=1 \
  net.ipv6.conf.default.accept_ra=1 net.ipv6.conf.all.accept_source_route=1 kernel.kptr_restrict=0 \
  kernel.yama.ptrace_scope=0 net.ipv4.conf.default.log_martians=0 net.ipv4.conf.default.accept_source_route=1 \
  fs.suid_dumpable=2 net.ipv4.tcp_syncookies=0 kernel.sysrq=176 net.core.bpf_jit_harden=0; do
  sysctl -q -w "$kv"
done
# Only udf is loaded: the network-protocol control FAILs on an available,
# install-enabled module without a load, and a loaded sctp is held in use on
# the runner, so its unload fails the block (CI run 39184265939).
modprobe --ignore-install udf
systemctl is-active --quiet auditd || systemctl start auditd
for f in /var/log/audit/audit.log /boot/grub/grub.cfg /etc/ssh/sshd_config.d/50-cloudimg-settings.conf; do
  test -e "$f" || { echo "runner.sh: $f is missing (installed auditd; the runner image is expected to ship the rest)" >&2; exit 1; }
done
chmod 644 /boot/grub/grub.cfg /var/log/audit/audit.log /etc/crontab /etc/rsyslog.conf /etc/hosts
chgrp shadow /etc/shadow && chmod 640 /etc/shadow   # the stock-FAIL scripted controls the repair run fixed (S-18)
install -m 644 /dev/null /etc/inetd.conf
sed -i 's/^ClientAliveInterval .*/ClientAliveInterval 900/' /etc/ssh/sshd_config.d/50-cloudimg-settings.conf
if grep -q '^UMASK' /etc/login.defs; then sed -i 's/^UMASK.*/UMASK 002/' /etc/login.defs; else printf 'UMASK 002\n' >> /etc/login.defs; fi
