# fspke examples

These examples are intended to illustrate usage of the forward secure PKE
implementation

# Tutorial

NOTE : the example programs are not built by default. If you want to build the
examples you need to ensure that you passed **--enable-examples** as a command line
option to the **configure** script. The examples are intended to be just that,
examples. While the example programs are intended to demonstrate a practical,
working and complete cryptosystem, they haven't been audited and implement
a rudimentary interface which leaves several details (e.g. agreeing on the scale
of intervals, authenticity of keys, securing private keys, destroying outdated
private keys) up to the user.

## Creating Keys

1. Create a public and private key pair

    As with most cryptography examples we have the situation where Alice wishes
    to send a message to Bob. In order for this to happen, Bob must have created
    a private key and then derive a public key (which he provides Alice). It is
    not necessary that 
    
    ```
    ./chk_gen > bob.privkey
    ./chk_pub --file bob.privkey > bob.pubkey
    cat bob.privkey
    cat bob.pubkey
    ```
    
    You'll notice that the private key is significantly larger than the public
    key. The default configuration will allow >16 million intervals (and
    contains up to 91 secrets to enable derivation of the individual interval
    keys).

## Sending a message

1. Encode the Message

    Alice encodes a message to Bob, in this case the message is encoded for a
    specific interval (an integer value). Once the message is encoded it can
    be delivered by any means to Bob. The contents of the message cannot be
    decoded without access to the private key.

    ```
    echo "Hello, Bob!" | ./chk_enc --interval=10 --key=bob.pubkey > ctext10
    cat ctext10
    ```

1. Decode the message

    Bob can use his private key to decode the message. Simple enough.
    
    ```
    cat ctext10 | ./chk_dec --key=bob.privkey
    ```

## Implementing forward security

Up to this point, any Public Key Encryption (PKE) scheme could have enabled
Alice and Bob to agree on a key such that Alice could encrypt a message
that only Bob could (practically) decrypt. What makes this particular scheme
unique is that Bob can update his private key such that he (or any attacker
who was able to obtain his key by any means, e.g. <https://xkdc>) can decode
future messages but can no longer decrypt messages from the past.

1. Derive a private key for an interval (in the future)

    After reading Alice's initial message, Bob generates a new private key
    which will work for future messages only (of course for this to be secure
    Bob would have to also securely erase his previous private key)
    
    ```
    cat bob.privkey | ./chk_der --interval=20 > bob20.privkey
    cat bob20.privkey
    ```

1. Encode a message for the future

    At some point of time in the future Alice decides to encode another
    message for Bob, and sends it to him.
    
    ```
    echo "Bye, Bob!" | ./chk_enc --interval=30 --key=bob.pubkey > ctext30
    cat ctext30
    ```

1. Verify that private keys can only decode for newer (greater) intervals

    Bob can verify that private keys can decode messages for newer intervals
    but cannot decode messages from the past.
    ```
    cat ctext10 | ./chk_dec --key=bob.privkey
    cat ctext10 | ./chk_dec --key=bob20.privkey
    cat ctext30 | ./chk_dec --key=bob.privkey
    cat ctext30 | ./chk_dec --key=bob20.privkey
    ```

    From this example, note that the original (interval 0) private key can
    decrypt both messages, but the newer (interval 20) private key can only
    decrypt messages from the future (ctext30), whereas messages from the past
    (ctext) are forward secure. So, presuming the older private key material is
    truly deleted, even if your private key is compromised older messages
    cannot be decrypted.

For more information on the algorithm and associated security proof, please
refer to ["A Forward-Secure Public Key Encryption Scheme"; Ran Canetti, Shai Halevi and Jonathan Katz](https://eprint.iacr.org/2003/083.pdf)
