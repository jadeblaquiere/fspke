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

There are <examples> provided which are intended to illustrate how the library
can be used to generate keypairs, update private keys and then use these keys
to encode and decode messages.
