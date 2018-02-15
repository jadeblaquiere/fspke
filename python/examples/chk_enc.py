#BSD 3-Clause License
#
# Copyright (c) 2018, Joseph deBlaquiere <jadeblaquiere@yahoo.com>
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of ecpy nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from FSPKE import CHKPKE, Element
from argparse import ArgumentParser
import base64
import sys
from hashlib import sha256
import asn1
import pysodium

desc = ('chk-enc encrypts a message using AES encryption based on a '
        'random key and then encrypts that random key using the CHK '
        'forward secure encryption scheme. Output is DER encoded '
        'and PEM-wrapped')

parser = ArgumentParser(description=desc)
parser.add_argument('-k', '--key', default=None, help='file path for file containing public key')
parser.add_argument('-i', '--interval', type=int, default=0, help='interval value to encrypt for')
parser.add_argument('-f', '--file', default=None, help='read message plaintext from file instead of stdin')
clargs = parser.parse_args()

if clargs.key is None:
    sys.exit('Error: -k / --key option for public key file is mandatory.')

with open(clargs.key, 'r') as keyfile:
    PEMkey=keyfile.read()
DERkey = base64.b64decode(PEMkey.split('-----')[2].encode())
try:
    pubkey = CHKPKE(pubkey=DERkey)
except ValueError:
    sys.exit('Error: Unable to import public key, aborting.')

if pubkey is None:
    sys.exit('Error: Unable to import public key, aborting.')

if clargs.file is None:
    message = sys.stdin.read()
else:
    with open(clargs.file, 'r') as msgfile:
        message=msgfile.read()

if (message is None) or (len(message) == 0):
    sys.exit('Error: Plaintext length 0, aborting.')

# derive a random shared key as sha256(Element().random().to_bytes)
e = Element(pubkey).random()
chachakey = sha256(e.to_bytes()).digest()

# encrypt shared secret
enckey = pubkey.encrypt(e, clargs.interval)

# generate a random 64 bit 
nonce = pysodium.randombytes(pysodium.crypto_aead_chacha20poly1305_NPUBBYTES)
assert pysodium.crypto_aead_chacha20poly1305_NPUBBYTES == 8

# write additional data into a single DER structure
encoder = asn1.Encoder()
encoder.start()
encoder.enter(asn1.Numbers.Sequence)
encoder.write(enckey, asn1.Numbers.OctetString)
encoder.write(nonce, asn1.Numbers.OctetString)
encoder.write(clargs.interval, asn1.Numbers.Integer)
encoder.leave()
AD = encoder.output()

ctext = pysodium.crypto_aead_chacha20poly1305_encrypt(message.encode(), AD, nonce, chachakey)

# encode the whole contents, AD + ctext
encoder = asn1.Encoder()
encoder.start()
encoder.enter(asn1.Numbers.Sequence)
encoder.enter(asn1.Numbers.Sequence)
encoder.write(enckey, asn1.Numbers.OctetString)
encoder.write(nonce, asn1.Numbers.OctetString)
encoder.write(clargs.interval, asn1.Numbers.Integer)
encoder.leave()
encoder.write(ctext, asn1.Numbers.OctetString)
encoder.leave()
DERmsg = encoder.output()

print('-----BEGIN CHK ENCRYPTED MESSAGE-----')
print(base64.b64encode(DERmsg).decode())
print('-----END CHK ENCRYPTED MESSAGE-----')
