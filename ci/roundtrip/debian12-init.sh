#!/bin/sh
# Seed debian12-init for the round trip (3D-2b §4). Runs inside the container from /ci.
# Packages and unit lists are the Task 1 probe's measurements. atftpd only: tftpd-hpa
# conflicts with it. The four NIS units are enable-only: they cannot start without a NIS
# domain. nfs-kernel-server.service is an alias of nfs-server.service, so the settle list
# names the real unit (the body skips the alias; the alias name is still recorded).
# No UMASK seed: Debian 12 stacks no pam_umask, so umask_policy cannot pass here.
# The image ships /etc/machine-id empty (see the Dockerfile).
set -eu
START_UNITS="autofs.service nfs-server.service rpcbind.socket rpcbind.service snmpd.service atftpd.socket atftpd.service vsftpd.service postfix@-.service"
ENABLE_ONLY_UNITS="ypserv.service ypbind.service ypxfrd.service yppasswdd.service"
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod 755 /usr/sbin/policy-rc.d
apt-get update -qq
# postfix installs without a prompt as a local-only system; its master runs
# under postfix@-.service (postfix.service is a /bin/true wrapper, O-58)
echo 'postfix postfix/main_mailer_type select Local only' | debconf-set-selections
echo 'postfix postfix/mailname string ci.example' | debconf-set-selections
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends autofs nfs-kernel-server rpcbind nis snmpd atftpd sudo cron rsyslog vsftpd postfix
rm -f /usr/sbin/policy-rc.d
systemctl reset-failed
# 3D-2d: vsftpd allows anonymous logins (stock is NO) and both daemons listen on
# IPv4 only, whatever IPv6 the docker gives the container (O-37, O-59).
for kv in anonymous_enable=YES listen=YES listen_ipv6=NO; do
  if grep -q "^${kv%%=*}=" /etc/vsftpd.conf; then sed -i "s/^${kv%%=*}=.*/$kv/" /etc/vsftpd.conf; else printf '%s\n' "$kv" >> /etc/vsftpd.conf; fi
done
postconf -e inet_protocols=ipv4
for u in $START_UNITS; do systemctl enable --now "$u"; done
for u in $ENABLE_ONLY_UNITS; do systemctl enable "$u"; done
chmod 664 /etc/passwd
chmod 666 /etc/services
install -m 644 /dev/null /etc/hosts.lpd
chmod 644 /etc/hosts
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
install -m 666 /dev/null /var/log/ci.log
bad=0
for u in $START_UNITS; do s=$(systemctl is-active "$u" 2>/dev/null) || :; [ "$s" = active ] || { echo "seed: $u is ${s:-unknown}, want active" >&2; bad=1; }; done
for u in $ENABLE_ONLY_UNITS; do s=$(systemctl is-active "$u" 2>/dev/null) || :; [ "$s" = inactive ] || { echo "seed: $u is ${s:-unknown}, want inactive" >&2; bad=1; }; done
exit "$bad"
