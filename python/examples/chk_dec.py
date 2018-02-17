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


def ensure_tag(decoder, expected):
    tag = decoder.peek()
    if tag.nr != expected:
        raise ValueError("Error in DER format, expected tag %d, got %d" %
                         (expected, tag.nr))


desc = ('chk-dec decrypts a message encrypted by chk-enc using the CHK '
        'forward secure encryption scheme.')

parser = ArgumentParser(description=desc)
parser.add_argument('-k', '--key', default=None, help='file path for file containing private key')
parser.add_argument('-f', '--file', default=None, help='read ciphertext from file instead of stdin')
clargs = parser.parse_args()

if clargs.key is None:
    sys.exit('Error: -k / --key option for public key file is mandatory.')

with open(clargs.key, 'r') as keyfile:
    PEMkey=keyfile.read()
DERkey = base64.b64decode(PEMkey.split('-----')[2].encode())
try:
    privkey = CHKPKE(privkey=DERkey)
except ValueError:
    sys.exit('Error: Unable to import private key, aborting.')

if privkey is None:
    sys.exit('Error: Unable to import private key, aborting.')

if clargs.file is None:
    PEMtxt = sys.stdin.read()
else:
    with open(clargs.file, 'r') as msgfile:
        PEMtxt=msgfile.read()

DERtxt = base64.b64decode(PEMtxt.split('-----')[2].encode())

decoder = asn1.Decoder()
decoder.start(DERtxt)
ensure_tag(decoder, asn1.Numbers.Sequence)
decoder.enter()
ensure_tag(decoder, asn1.Numbers.Sequence)
decoder.enter()
ensure_tag(decoder, asn1.Numbers.OctetString)
tag, enckey = decoder.read()
ensure_tag(decoder, asn1.Numbers.OctetString)
tag, nonce = decoder.read()
ensure_tag(decoder, asn1.Numbers.Integer)
tag, interval = decoder.read()
decoder.leave()
ensure_tag(decoder, asn1.Numbers.OctetString)
tag, ctext = decoder.read()

# re-write additional data into a single DER structure
encoder = asn1.Encoder()
encoder.start()
encoder.enter(asn1.Numbers.Sequence)
encoder.write(enckey, asn1.Numbers.OctetString)
encoder.write(nonce, asn1.Numbers.OctetString)
encoder.write(interval, asn1.Numbers.Integer)
encoder.leave()
AD = encoder.output()

try:
    e = privkey.decrypt(enckey, interval)
except ValueError:
    print("<Error>: Unable to derive key for interval")
    sys.exit(1)
chachakey = sha256(e.to_bytes()).digest()

message = pysodium.crypto_aead_chacha20poly1305_ietf_decrypt(ciphertext=ctext,
    ad=AD, nonce=nonce, key=chachakey)

print(message.decode(), end='')
