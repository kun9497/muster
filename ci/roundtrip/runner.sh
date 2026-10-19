#!/bin/sh
# runner.sh seeds the GitHub runner VM for the fix-roundtrip host row
# (3D-2c §5). It is idempotent: it removes every file a review script wrote,
# puts back the stock modes the repair run tightened, then applies every seed
# again, so the failure run plans every seeded block (S-18). It never writes
# -e 2 or --loginuid-immutable anywhere (3D-2d §5).
set -eu
export DEBIAN_FRONTEND=noninteractive
if ! command -v auditctl >/dev/null 2>&1 || ! dpkg -s libpam-pwquality >/dev/null 2>&1; then apt-get update -q && apt-get install -y -q auditd libpam-pwquality; fi
rm -f /etc/sysctl.d/99-muster-*.conf /etc/modprobe.d/99-muster-*.conf \
  /etc/ssh/sshd_config.d/00-muster-session.conf /etc/security/pwquality.conf.d/99-muster.conf   /etc/audit/rules.d/50-muster.rules
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
# 3D-2d: the first run keeps the pristine auditd.conf and /etc/default/useradd
# where no body writes; every run puts them back before seeding again.
s=/var/lib/muster-ci
mkdir -p "$s"
[ -e "$s/auditd.conf" ] || cp -p /etc/audit/auditd.conf "$s/auditd.conf"
if [ ! -e "$s/useradd" ] && [ ! -e "$s/useradd.absent" ]; then
  if [ -e /etc/default/useradd ]; then cp -p /etc/default/useradd "$s/useradd"; else : > "$s/useradd.absent"; fi
fi
cp -p "$s/auditd.conf" /etc/audit/auditd.conf
if [ -e "$s/useradd.absent" ]; then rm -f /etc/default/useradd; else cp -p "$s/useradd" /etc/default/useradd; fi
# audit_rules_loaded: the stock set loaded (its -D leaves the kernel list
# empty), then a backlog limit no persisted file carries, so only the
# rollback's replay of the recorded status puts it back (case c).
augenrules --load
auditctl -b 4321 >/dev/null
# audit_disk_actions: a full-disk action outside the list; auditd rereads it.
if grep -Eiq '^[[:space:]]*disk_full_action[[:space:]]*=' /etc/audit/auditd.conf; then
  sed -i -E 's/^[[:space:]]*disk_full_action[[:space:]]*=.*/disk_full_action = suspend/I' /etc/audit/auditd.conf
else
  printf 'disk_full_action = suspend\n' >> /etc/audit/auditd.conf
fi
auditctl --signal reload
# account_inactivity_lock: no inactivity bound on any account the body
# judges (uid 0 or at least UID_MIN, a shell listed in /etc/shells that is not
# nologin or false, a shadow row).
m=$(awk '$1 == "UID_MIN" && $2 ~ /^[0-9]+$/ { print $2; exit }' /etc/login.defs)
awk -F: -v m="${m:-1000}" '
  FILENAME == ARGV[1] { l = $0; sub(/^[[:space:]]+/, "", l); sub(/[[:space:]]+$/, "", l); if (l != "" && l !~ /^#/) sh[l] = 1; next }
  FILENAME == ARGV[2] { if (NF >= 8 && $1 != "" && $1 !~ /^#/) sd[$1] = 1; next }
  $0 ~ /^#/ || NF < 7 || $1 == "" { next }
  { u = $3 + 0; if (u > 0 && u < m + 0) next; if ($7 == "" || $7 ~ /\/(nologin|false)$/ || !($7 in sh) || !($1 in sd)) next; print $1 }
' /etc/shells /etc/shadow /etc/passwd | while IFS= read -r a; do chage -I -1 -- "$a"; done
# auditd_active: disabled, kept running (nothing may stop it again).
systemctl disable auditd
for f in /var/log/audit/audit.log /boot/grub/grub.cfg /etc/ssh/sshd_config.d/50-cloudimg-settings.conf; do
  test -e "$f" || { echo "runner.sh: $f is missing (installed auditd; the runner image is expected to ship the rest)" >&2; exit 1; }
done
chmod 644 /boot/grub/grub.cfg /var/log/audit/audit.log /etc/crontab /etc/rsyslog.conf /etc/hosts
chgrp shadow /etc/shadow && chmod 640 /etc/shadow   # the stock-FAIL scripted controls the repair run fixed (S-18)
install -m 644 /dev/null /etc/inetd.conf
sed -i 's/^ClientAliveInterval .*/ClientAliveInterval 900/' /etc/ssh/sshd_config.d/50-cloudimg-settings.conf
if grep -q '^UMASK' /etc/login.defs; then sed -i 's/^UMASK.*/UMASK 002/' /etc/login.defs; else printf 'UMASK 002\n' >> /etc/login.defs; fi
