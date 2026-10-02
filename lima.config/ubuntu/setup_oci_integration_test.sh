#!/bin/sh

set -eu -o pipefail

CONTAINERD_2_YOUKI_GO_VERSION="1.20.12"
CONTAINERD_2_YOUKI_CONTAINERD_VERSION="1.7.11"

if [ $(id -u) -ne 0 ]; then
    echo "You must run this script as root." >&2
    exit 1
fi

if [ ! command -v youki ]; then
    echo "You must install youki first" >&2
    exit 1
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
      GOARCH="amd64"
      ;;
    aarch64)
      GOARCH="arm64"
      ;;
    *)
      echo "Unsupported architecture: $ARCH" 2>&2
      exit 1
      ;;
esac

rm -rf /usr/local/go
curl -sSfL https://go.dev/dl/go${CONTAINERD_2_YOUKI_GO_VERSION}.linux-${GOARCH}.tar.gz | tar -C /usr/local -xzf -
echo 'export PATH=/usr/local/go/bin:$PATH' >> $HOME/.bashrc
echo 'export GOPATH=$HOME/go' >> $HOME/.bashrc

export PATH=/usr/local/go/bin:$PATH
export GOPATH=$HOME/go

git clone https://github.com/containerd/containerd \
  /root/go/src/github.com/containerd/containerd \
  -b v${CONTAINERD_2_YOUKI_CONTAINERD_VERSION}

cd /root/go/src/github.com/containerd/containerd
make
make binaries
make install
./script/setup/install-cni
./script/setup/install-critools
rm -rf /bin/runc /sbin/runc /usr/sbin/runc /usr/bin/runc
ln -s /vagrant/youki/youki /usr/bin/runc
