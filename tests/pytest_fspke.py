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

import unittest
from FSPKE import CHKPKE, Element
from binascii import hexlify, unhexlify

class TestCHKPKE(unittest.TestCase):

    def setUp(self):
        self.pke = CHKPKE(128,100,4,8)

    def test_pubkey_export(self):
        self.assertIsNotNone(self.pke.pubkey())

    def test_privkey_export(self):
        self.assertIsNotNone(self.pke.privkey())
        self.assertIsNotNone(self.pke.privkey(0))
        self.assertEqual(self.pke.privkey(0),self.pke.privkey(0))
        self.assertIsNotNone(self.pke.privkey(7))
        self.assertNotEqual(self.pke.privkey(0),self.pke.privkey(1))
        with self.assertRaises(ValueError):
            b = self.pke.privkey(-1)
            b = self.pke.privkey(4096)
            b = self.pke.privkey(1,4096)
            b = self.pke.privkey(11,10)

    def test_pubkey_export_import(self):
        pub = self.pke.pubkey()
        copy = CHKPKE(pubkey=pub)
        self.assertEqual(pub, copy.pubkey())
        with self.assertRaises(ValueError):
            cpriv = copy.privkey()
        self.assertIsNotNone(self.pke.privkey())

    def test_privkey_export_import(self):
        priv = self.pke.privkey()
        copy = CHKPKE(privkey=priv)
        self.assertEqual(priv, copy.privkey())
        subkey = self.pke.privkey(3,4092)
        copy = CHKPKE(privkey=subkey)
        self.assertEqual(subkey, copy.privkey(3,4092))
        with self.assertRaises(ValueError):
            b = copy.privkey()
            b = copy.privkey(3)
            b = copy.privkey(0,4092)
            b = copy.privkey(2,4093)
        subkey = copy.privkey(5,4090)
        copy = CHKPKE(privkey=subkey)
        self.assertEqual(subkey, copy.privkey(5,4090))
        with self.assertRaises(ValueError):
            b = copy.privkey(4,4091)

class TestElement(unittest.TestCase):

    def setUp(self):
        self.pke = CHKPKE(128,100,4,8)

    def test_element_export(self):
        self.e = Element(self.pke)
        self.assertIsNotNone(self.e.to_bytes())
        self.ee = Element(self.pke, self.e.to_bytes())
        self.assertIsNotNone(self.ee.to_bytes())
        with self.assertRaises(TypeError):
            f = Element(0)
            f = Element(self.e)

class TestEncryptDecrypt(unittest.TestCase):

    def setUp(self):
        self.pke = CHKPKE(128,100,4,8)

    def test_encrypt_decrypt(self):
        pubpke = CHKPKE(pubkey=self.pke.pubkey())
        self.assertIsNotNone(self.pke.privkey(12,12))
        with self.assertRaises(ValueError):
            cpriv = pubpke.privkey(12,12)
        e = Element(self.pke).random()
        m = pubpke.encrypt(e, 12);
        f = self.pke.decrypt(m, 12);
        self.assertEqual(e.to_bytes(), f.to_bytes())
        for i in range(0,4096):
            if i != 12:
                g = self.pke.decrypt(m, i);
                self.assertNotEqual(e.to_bytes(), g.to_bytes())
        with self.assertRaises(ValueError):
            h = pubpke.decrypt(m, 12)


if __name__ == '__main__':
    unittest.main()
