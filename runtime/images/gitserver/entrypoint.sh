#!/bin/bash
# git over ssh; bare repos seeded from /provision/seed at first boot
set -e
mkdir -p /run/sshd
useradd -m -s /usr/bin/git-shell git 2>/dev/null || true
echo "git:${GIT_PASS}" | chpasswd
mkdir -p /srv/git
for d in /provision/seed/*/; do
  name=$(basename "$d")
  cd "$d"
  git init -q .
  git add -A
  git -c user.name=dev -c user.email=dev@nimbus.local commit -qm "seed"
  git clone -q --bare . "/srv/git/${name}.git"
done
exec /usr/sbin/sshd -D -e
