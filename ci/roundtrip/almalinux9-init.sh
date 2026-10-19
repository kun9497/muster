#!/bin/sh
# Seed almalinux9-init for the round trip (3D-2b §4). Runs inside the container from /ci.
# Packages and unit lists are the Task 1 probes' measurements (default repositories only;
# 3D-2b, then 3D-2c: authselect and passwd bring pam_faillock and /etc/pam.d/passwd).
# The image ships /etc/machine-id empty, so each container boots with its own id.
set -eu
START_UNITS="sshd.service autofs.service nfs-server.service rpcbind.socket rpcbind.service snmpd.service telnet.socket tftp.socket tftp.service vsftpd.service postfix.service"
ENABLE_ONLY_UNITS=""
dnf install -y -q openssh-server autofs nfs-utils rpcbind net-snmp telnet-server tftp-server acl vsftpd postfix
ssh-keygen -A
# 3D-2d: vsftpd allows anonymous logins (stock is NO) and both daemons listen on
# IPv4 only, whatever IPv6 the docker gives the container (O-37, O-59).
for kv in anonymous_enable=YES listen=YES listen_ipv6=NO; do
  if grep -q "^${kv%%=*}=" /etc/vsftpd/vsftpd.conf; then sed -i "s/^${kv%%=*}=.*/$kv/" /etc/vsftpd/vsftpd.conf; else printf '%s\n' "$kv" >> /etc/vsftpd/vsftpd.conf; fi
done
postconf -e inet_protocols=ipv4
for u in $START_UNITS; do systemctl enable --now "$u"; done
for u in $ENABLE_ONLY_UNITS; do systemctl enable "$u"; done
printf 'PermitRootLogin yes\n' > /etc/ssh/sshd_config.d/99-ci.conf
chmod 664 /etc/passwd
chmod 666 /etc/services
install -m 644 /dev/null /etc/hosts.lpd
chmod 644 /etc/hosts
dnf install -y -q sudo cronie rsyslog authselect passwd
chmod 644 /etc/sudoers
install -m 644 /dev/null /etc/inetd.conf
# 3D-2d: a no_root_squash export (O-60: the overlay root cannot be exported, a
# tmpfs can), at mode 666 so the mode half still runs.
mkdir -p /srv/ci
mountpoint -q /srv/ci || mount -t tmpfs tmpfs /srv/ci
install -m 666 /dev/null /etc/exports
printf '/srv/ci 192.0.2.0/24(rw,no_root_squash,fsid=1)\n' > /etc/exports
exportfs -ra
printf '+\n' > /etc/hosts.equiv; chmod 644 /etc/hosts.equiv
chmod 644 /etc/vsftpd/ftpusers
install -m 666 /dev/null /var/log/ci.log
sed -i -E 's/^([[:space:]]*UMASK[[:space:]]+)[0-9]+/\1002/' /etc/login.defs
authselect select minimal with-faillock --force
printf 'deny = 99\n' >> /etc/security/faillock.conf
# its own drop-in: 99-ci.conf keeps PermitRootLogin yes, and this one sorts after 00-muster-session.conf
printf 'ClientAliveInterval 900\n' > /etc/ssh/sshd_config.d/99-ci-session.conf
# a hashed account changed today, with a random password
useradd -m ci
printf 'ci:%s\n' "$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')" | chpasswd
bad=0
for u in $START_UNITS; do s=$(systemctl is-active "$u" 2>/dev/null) || :; [ "$s" = active ] || { echo "seed: $u is ${s:-unknown}, want active" >&2; bad=1; }; done
for u in $ENABLE_ONLY_UNITS; do s=$(systemctl is-active "$u" 2>/dev/null) || :; [ "$s" = inactive ] || { echo "seed: $u is ${s:-unknown}, want inactive" >&2; bad=1; }; done
exit "$bad"
