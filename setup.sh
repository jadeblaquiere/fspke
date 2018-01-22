#!/bin/env sh

sudo apt-get update
sudo apt-get -y install check
sudo apt-get -y install libtasn1-6-dev libtasn1-bin
git clone https://github.com/jadeblaquiere/ecclib.git
cd libecc
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
