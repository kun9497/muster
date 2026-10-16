#!/bin/sh
# Seed almalinux9-init for the round trip (3D-2b §4). Runs inside the container from /ci.
# Packages and unit lists are the Task 1 probes' measurements (default repositories only;
# 3D-2b, then 3D-2c: authselect and passwd bring pam_faillock and /etc/pam.d/passwd).
# The image ships /etc/machine-id empty, so each container boots with its own id.
set -eu
START_UNITS="sshd.service autofs.service nfs-server.service rpcbind.socket rpcbind.service snmpd.service telnet.socket tftp.socket tftp.service"
ENABLE_ONLY_UNITS=""
dnf install -y -q openssh-server autofs nfs-utils rpcbind net-snmp telnet-server tftp-server acl
ssh-keygen -A
for u in $START_UNITS; do systemctl enable --now "$u"; done
for u in $ENABLE_ONLY_UNITS; do systemctl enable "$u"; done
printf 'PermitRootLogin yes\n' > /etc/ssh/sshd_config.d/99-ci.conf
chmod 664 /etc/passwd
chmod 666 /etc/services
install -m 644 /dev/null /etc/hosts.lpd
chmod 644 /etc/hosts
dnf install -y -q sudo cronie rsyslog vsftpd authselect passwd
chmod 644 /etc/sudoers
install -m 644 /dev/null /etc/inetd.conf
install -m 666 /dev/null /etc/exports
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
