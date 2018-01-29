#!/bin/env sh

sudo apt-get update
sudo apt-get -y install check
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
./configure --prefix=/usr
make
sudo make install
cd ..
# libpopt, libb64, libsodium used for examples only
sudo apt-get -y install libpopt-dev
sudo apt-get -y install libb64-dev
sudo add-apt-repository -y ppa:chris-lea/libsodium
sudo apt-get update
sudo apt-get -y install libsodium-dev
