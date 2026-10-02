#!/bin/sh

set -eu

sudo apt update
sudo apt install -y \
	pkgconf  \
	build-essential \
	just \
	libseccomp-dev \
	libelf-dev

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
echo 'export PATH=$HOME/.cargo/bin:$PATH' >> ~/.bashrc
export PATH=$HOME/.cargo/bin:$PATH

git clone https://github.com/youki-dev/youki
cd youki
just youki-release # or youki-dev
sudo cp ./youki /usr/local/bin
