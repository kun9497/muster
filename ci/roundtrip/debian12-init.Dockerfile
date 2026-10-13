FROM debian:12
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv netbase acl \
 && systemctl mask getty@tty1.service console-getty.service \
 && : > /etc/machine-id && rm -f /var/lib/dbus/machine-id
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
