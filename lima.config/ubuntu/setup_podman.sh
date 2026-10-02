#!/bin/sh

set -eu

if [[ $(id -u) -ne 0 ]]; then
  echo "You must run this script as root." >&2
  exit 1
fi

sudo apt update
sudo apt install -y podman

sudo mkdir -p /etc/containers/containers.conf.d

sudo cat > /etc/containers/containers.conf.d/50-youki.conf <<EOF
# [engine]
# runtime = "youki"

[engine.runtimes]
youki = [
  "/usr/local/bin/youki",
]
EOF
