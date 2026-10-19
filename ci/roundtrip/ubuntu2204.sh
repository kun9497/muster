#!/bin/sh
# Seed ubuntu2204 for the round trip (3D-2b §4). Runs inside the container from /ci.
# The non-init row: file and account controls only. netbase creates /etc/services; acl
# brings getfacl; sudo, cron and rsyslog bring the files their controls judge.
set -eu
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends netbase acl sudo cron rsyslog
chmod 664 /etc/passwd
chmod 666 /etc/services
install -m 644 /dev/null /etc/hosts.lpd
chmod 644 /etc/hosts
chmod 644 /etc/sudoers
install -m 644 /dev/null /etc/inetd.conf
install -m 666 /dev/null /var/log/ci.log
sed -i -E 's/^([[:space:]]*UMASK[[:space:]]+)[0-9]+/\1002/' /etc/login.defs
