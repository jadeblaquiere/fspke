//BSD 3-Clause License
//
//Copyright (c) 2018, jadeblaquiere
//All rights reserved.
//
//Redistribution and use in source and binary forms, with or without
//modification, are permitted provided that the following conditions are met:
//
//* Redistributions of source code must retain the above copyright notice, this
//  list of conditions and the following disclaimer.
//
//* Redistributions in binary form must reproduce the above copyright notice,
//  this list of conditions and the following disclaimer in the documentation
//  and/or other materials provided with the distribution.
//
//* Neither the name of the copyright holder nor the names of its
//  contributors may be used to endorse or promote products derived from
//  this software without specific prior written permission.
//
//THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
//AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
//IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
//FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
//DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
//CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
//OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package fsgo

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestCHKPKEGen(t *testing.T) {
	pke := CHKPKEGen(512, 384, 6, 16)
	if pke == nil {
		fmt.Println("Error: nil returned from Gen")
		t.FailNow()
	}
	if pke.Maxinterval() != ((1 << (6 * 4)) - 1) {
		fmt.Println("Error: Maxinterval mismatch")
		t.FailNow()
	}
	pke = CHKPKEGen(256, 192, 4, 8)
	if pke == nil {
		fmt.Println("Error: nil returned from Gen")
		t.FailNow()
	}
	if pke.Maxinterval() != ((1 << (4 * 3)) - 1) {
		fmt.Println("Error: Maxinterval mismatch")
		t.FailNow()
	}
	pke = CHKPKEGen(128, 96, 8, 4)
	if pke == nil {
		fmt.Println("Error: nil returned from Gen")
		t.FailNow()
	}
	if pke.Maxinterval() != ((1 << (8 * 2)) - 1) {
		fmt.Println("Error: Maxinterval mismatch")
		t.FailNow()
	}
}

func TestCHKPKEExportPubkey(t *testing.T) {
	pke := CHKPKEGen(128, 100, 6, 16)

	pubkeyDer, err := pke.ExportPubkey()
	if err != nil {
		fmt.Println("Error exporting Pubkey")
		t.FailNow()
	}
	fmt.Println("PubKey = ", hex.EncodeToString(pubkeyDer))
}

func TestCHKPKEExportPrivkey(t *testing.T) {
	pke := CHKPKEGen(128, 100, 6, 16)

	privkeyDer, err := pke.ExportPrivkey(0)
	if err != nil {
		fmt.Println("Error exporting Privkey")
		t.FailNow()
	}
	fmt.Println("PrivKey = ", hex.EncodeToString(privkeyDer))
}

func TestCHKPKEExportDelegatePrivkey(t *testing.T) {
	pke := CHKPKEGen(128, 100, 6, 16)

	privkeyDer, err := pke.ExportDelegatePrivkey(1, 123456)
	if err != nil {
		fmt.Println("Error exporting Privkey")
		t.FailNow()
	}
	fmt.Println("PrivKey = ", hex.EncodeToString(privkeyDer))
}

func TestCHKPKEExportImportPubkey(t *testing.T) {
	pke := CHKPKEGen(128, 100, 6, 16)

	pubkeyDer, err := pke.ExportPubkey()
	if err != nil {
		fmt.Println("Error exporting Pubkey")
		t.FailNow()
	}
	pke2, err := CHKPKEImportPubkey(pubkeyDer)
	if err != nil {
		fmt.Println("Error importing Pubkey")
		t.FailNow()
	}
	pubkey2Der, err := pke2.ExportPubkey()
	if err != nil {
		fmt.Println("Error exporting Pubkey2")
		t.FailNow()
	}
	if bytes.Compare(pubkeyDer, pubkey2Der) != 0 {
		fmt.Println("mismatch Pubkey != Pubkey2")
		t.FailNow()
	}
}

func TestCHKPKEExportImportPrivkey(t *testing.T) {
	pke := CHKPKEGen(128, 100, 6, 16)

	privkeyDer, err := pke.ExportPrivkey(0)
	if err != nil {
		fmt.Println("Error exporting Privkey")
		t.FailNow()
	}
	pke2, err := CHKPKEImportPrivkey(privkeyDer)
	if err != nil {
		fmt.Println("Error importing Privkey")
		t.FailNow()
	}
	privkey2Der, err := pke2.ExportPrivkey(0)
	if err != nil {
		fmt.Println("Error exporting Privkey2")
		t.FailNow()
	}
	if bytes.Compare(privkeyDer, privkey2Der) != 0 {
		fmt.Println("mismatch Privkey != Privkey2")
		t.FailNow()
	}
}

func TestCHKPKEEncryptDecrypt(t *testing.T) {
	pke := CHKPKEGen(128, 100, 4, 8)

	pubkeyDer, err := pke.ExportPubkey()
	if err != nil {
		fmt.Println("Error exporting Privkey")
		t.FailNow()
	}
	pub, err := CHKPKEImportPubkey(pubkeyDer)
	if err != nil {
		fmt.Println("Error importing Pubkey")
		t.FailNow()
	}
	e := pub.GenerateRandomElement()

	fmt.Println("Plaintext (in)  = ", hex.EncodeToString(e.ToBytes()))
	ct, err := pub.Encrypt(e, 10)
	if err != nil {
		fmt.Println("Error encrypting element")
		t.FailNow()
	}
	pt, err := pke.Decrypt(ct, 10)
	if err != nil {
		fmt.Println("Error decrypting element")
		t.FailNow()
	}
	fmt.Println("Plaintext (out) = ", hex.EncodeToString(pt.ToBytes()))
	if bytes.Compare(e.ToBytes(), pt.ToBytes()) != 0 {
		fmt.Println("mismatch initial plaintext != decrypted plaintext")
		t.FailNow()
	}
	for i := 0; i < 4096; i++ {
		if i != 10 {
			pt, err := pke.Decrypt(ct, int64(i))
			if err != nil {
				fmt.Println("Error decrypting element")
				t.FailNow()
			}
			if bytes.Compare(e.ToBytes(), pt.ToBytes()) == 0 {
				fmt.Println("Error: collision decrypting with wrong interval")
				t.FailNow()
			}
		}
	}
}
