#!/bin/bash
# real sshd; users provisioned from the world model at startup
set -e
mkdir -p /run/sshd
if [ -f /provision/users.txt ]; then
  while IFS=':' read -r user pass dept; do
    [ -z "$user" ] && continue
    id "$user" >/dev/null 2>&1 || useradd -m -s /bin/bash "$user"
    echo "$user:$pass" | chpasswd
  done < /provision/users.txt
fi
exec /usr/sbin/sshd -D -e
