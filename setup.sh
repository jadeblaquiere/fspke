#!/bin/env sh

sudo apt-get update
sudo apt-get install check
sudo apt-get install libtasn1-6-dev libtasn1-bin
git clone https://github.com/jadeblaquiere/libecc.git
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
