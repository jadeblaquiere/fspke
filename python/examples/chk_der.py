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
import sys

desc = ('chk-der derives a forward secure private key for an interval from '
        'a private key from a previous interval. Secrets for previous '
        'intervals are removed and the resulting key can no longer decrypt '
        'older messages')

parser = ArgumentParser(description=desc)
parser.add_argument('-s', '--start', type=int, default=0, help='starting interval value to derive new key, default=0')
parser.add_argument('-e', '--end', type=int, default=-1, help='ending interval value to derive new key, default=<last>')
parser.add_argument('-f', '--file', default=None, help='read private key from file instead of stdin')
clargs = parser.parse_args()

if clargs.file is None:
    PEMkey = sys.stdin.read()
else:
    with open(clargs.file, 'r') as keyfile:
        PEMkey=keyfile.read()

DERkey = base64.b64decode(PEMkey.split('-----')[2].encode())

try:
    privkey = CHKPKE(privkey=DERkey)
except ValueError:
    sys.exit('Error: Unable to import private key, aborting.')

if privkey is None:
    sys.exit('Error: Unable to import private key, aborting.')

if clargs.end < 0:
    DERkey = privkey.privkey(clargs.start)
else:
    DERkey = privkey.privkey(clargs.start, clargs.end)
print('-----BEGIN CHK PRIVATE KEY-----')
print(base64.b64encode(DERkey).decode())
print('-----END CHK PRIVATE KEY-----')
