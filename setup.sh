#!/bin/env sh

sudo apt-get update
sudo apt-get -y install check
# alternatively git clone git@gitlab.com:gnutls/libtasn1.git
sudo apt-get -y install libtasn1-6-dev libtasn1-bin
git clone https://github.com/jadeblaquiere/ecclib.git
cd ecclib
autoreconf --install
./configure --prefix=/usr
make
sudo make install
cd ..
git clone https://github.com/blynn/pbc.git
cd pbc
autoreconf --install
./configure --prefix=/usr --enable-safe-clean
make
sudo make install
cd ..
# libpopt, libb64, libsodium used for examples only
# alternatively brew install popt
sudo apt-get -y install libpopt-dev
# alternatively https://github.com/transmission/libb64.git
sudo apt-get -y install libb64-dev
# need to build libsodium from source - expect v1.0.16
# alternatively https://github.com/jedisct1/libsodium.git
mkdir sodium-build
cd sodium-build
wget http://archive.ubuntu.com/ubuntu/pool/main/libs/libsodium/libsodium_1.0.16.orig.tar.gz
tar xvf libsodium_1.0.16.orig.tar.gz
cd libsodium-1.0.16
autoreconf --install
./configure --prefix=/usr
make
sudo make install
cd ../..