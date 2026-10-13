#!/bin/sh
# Seed debian12-init for the round trip (3D-2b §4). Runs inside the container from /ci.
# Packages and unit lists are the Task 1 probe's measurements. atftpd only: tftpd-hpa
# conflicts with it. The four NIS units are enable-only: they cannot start without a NIS
# domain. nfs-kernel-server.service is an alias of nfs-server.service, so the settle list
# names the real unit (the body skips the alias; the alias name is still recorded).
# The image ships /etc/machine-id empty (see the Dockerfile).
set -eu
START_UNITS="autofs.service nfs-server.service rpcbind.socket rpcbind.service snmpd.service atftpd.socket atftpd.service"
ENABLE_ONLY_UNITS="ypserv.service ypbind.service ypxfrd.service yppasswdd.service"
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod 755 /usr/sbin/policy-rc.d
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends autofs nfs-kernel-server rpcbind nis snmpd atftpd
rm -f /usr/sbin/policy-rc.d
systemctl reset-failed
for u in $START_UNITS; do systemctl enable --now "$u"; done
for u in $ENABLE_ONLY_UNITS; do systemctl enable "$u"; done
chmod 664 /etc/passwd
chmod 666 /etc/services
install -m 644 /dev/null /etc/hosts.lpd
chmod 644 /etc/hosts
bad=0
for u in $START_UNITS; do s=$(systemctl is-active "$u" 2>/dev/null) || :; [ "$s" = active ] || { echo "seed: $u is ${s:-unknown}, want active" >&2; bad=1; }; done
for u in $ENABLE_ONLY_UNITS; do s=$(systemctl is-active "$u" 2>/dev/null) || :; [ "$s" = inactive ] || { echo "seed: $u is ${s:-unknown}, want inactive" >&2; bad=1; }; done
exit "$bad"
