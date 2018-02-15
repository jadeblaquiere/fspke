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

from FSPKE import CHKPKE
from argparse import ArgumentParser
import base64

desc = ('chk-gen creates new Forward Secure PKE Private Key set based on the '
        'cryptosystem described by Canetti, Halevi and Katz in 2003. The '
        'output is a private key. The key can be pruned to be forward secure '
        'based on interval where there are (order ** depth) intervals')

parser = ArgumentParser(description=desc)
parser.add_argument('-d', '--depth', type=int, default=6, help='depth of btree used to derive keys')
parser.add_argument('-o', '--order', type=int, default=16, help='order of btree used to derive keys')
parser.add_argument('-q', '--qbits', type=int, default=512, help='bitsize of prime field')
parser.add_argument('-r', '--rbits', type=int, default=400, help='bitsize of order of curve groups')
clargs = parser.parse_args()

privkey = CHKPKE(clargs.qbits, clargs.rbits, clargs.depth, clargs.order)
DERkey = privkey.privkey()
print('-----BEGIN CHK PRIVATE KEY-----')
print(base64.b64encode(DERkey).decode())
print('-----END CHK PRIVATE KEY-----')
