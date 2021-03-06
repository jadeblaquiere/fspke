# fspke

C library implementing forward-secure public key cryptosystem as described
by Canetti, Halevi and Katz (CHK) in 2003 <https://eprint.iacr.org/2003/083.pdf>.

Forward secrecy (or forward security) in a cryptosystem implies that if at
some point in time somebody's secret key is obtained that past messages
cannot be decrypted. The CHK construction uses a binary tree Hierarchical
Identity Based Encryption scheme to derive a set of secrets from a base secret
in a manner such that the encryption algorithm depends only on the root public
key while the secret key for any node is derived from it's parent node's secret
via a one-way trapdoor function. This construction allows derivation of a secret
key which can decode messages for the current and all future time intervals
but cannot decode messages for past intervals (as that would require deriving
the parent secret from a child node).

This implementation relies on the excellent work of several others:
* The initial construction of Canetti, Halevi and Katz.
* Ben Lynn's Pairing Based Cryptography library: <https://crypto.stanford.edu/pbc/>
* Thomas Icart, Eric Brier and friends work in uniform hashing into elliptic curve groups <https://eprint.iacr.org/2009/340.pdf>

There are [examples](examples) provided which are intended to illustrate how the library
can be used to generate keypairs, update private keys and then use these keys
to encode and decode messages.

# Building the library

The build process is implemented using GNU autotools, so it should in theory
be portable to generally any common platform. There are a number of prerequisite
libraries which are used as a basis for implementation (e.g. gmp, pbc,
libtasn1, ecclib). The build process requires autotools and check (for unit testing).
The examples also require popt, libb64 and libsodium. There is a script called
[setup.sh](setup.sh) which will install all of these dependencies on a Ubuntu 14.04 platform.
Once you have all of these dependencies installed you should be able to build the
library and examples using something *like* the following commands:

```
autoreconf --install
./configure --prefix=/usr --enable-examples
make clean
make
sudo make install
```

# Installing Python bindings

Once the C library itself is installed, the python3 bindings module can be built
and installed via the setup.py or pip using something *like* either of these:

1. Via setup.py directly

    ```
    python3 ./setup.py build
    sudo python3 ./setup.py install
    ```

1. Via pip

    ```
    sudo pip3 install .
    ```

The [python examples](python/examples) are intended to illustrate how the
library can be used via the python bindings

# Installing Go (golang) bindings

Once the C library itself is installed, the Go bindings can be set up using a
command *like* the following:

```
go get -d github.com/jadeblaquiere/fspke/fsgo
```

The [go examples](fsgo/cmd/) are intended to illustrate how the library can be
used via the go bindings

# running unit tests

If you would like to verify that the libraries were built correctly you can
execute all of the unit tests with commands *like*:

```
make check
python3 ./tests/pytest_fspke.py
(cd fsgo; go test)
```
