#!/bin/sh
# Seed ubuntu2204 for the round trip (3D-2b §4). Runs inside the container from /ci.
# The non-init row: file controls only. netbase creates /etc/services; acl brings getfacl.
set -eu
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends netbase acl
chmod 664 /etc/passwd
chmod 666 /etc/services
install -m 644 /dev/null /etc/hosts.lpd
chmod 644 /etc/hosts
