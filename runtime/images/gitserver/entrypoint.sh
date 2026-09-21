#!/bin/bash
# git over ssh; bare repos seeded from /provision/seed at first boot
set -e
mkdir -p /run/sshd
useradd -m -s /usr/bin/git-shell git 2>/dev/null || true
echo "git:${GIT_PASS}" | chpasswd
git config --global --add safe.directory '*'
mkdir -p /srv/git
for d in /provision/seed/*/; do
  name=$(basename "$d")
  if [ -d "/srv/git/${name}.git" ]; then continue; fi
  tmp=$(mktemp -d)
  cp -r "${d}." "$tmp/"
  git -C "$tmp" init -q .
  git -C "$tmp" add -A
  git -C "$tmp" -c user.name=dev -c user.email=dev@nimbus.local commit -qm "seed"
  git clone -q --bare "$tmp" "/srv/git/${name}.git"
  rm -rf "$tmp"
done
chown -R git:git /srv/git
exec /usr/sbin/sshd -D -e
