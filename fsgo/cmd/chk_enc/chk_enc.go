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

package main

import (
	"../shared"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"github.com/jadeblaquiere/fspke/fsgo"
	"golang.org/x/crypto/chacha20poly1305"
	"io/ioutil"
	"os"
)

func main() {
	var input []byte
	var keyb64 []byte
	var err error

	filepath := flag.String("file", "", "plaintext input")
	keyfile := flag.String("key", "", "public key input file path (default: read from stdin)")
	interval := flag.Int64("interval", 0, "interval for message encryption")
	flag.Parse()

	if len(*keyfile) == 0 {
		os.Stderr.WriteString("Error: -key option is mandatory")
		os.Exit(1)
	}
	keyb64, err = ioutil.ReadFile(*keyfile)
	shared.ExitOnError(err, "Error reading key from file")

	pubkey, err := shared.ReadB64Wrapped("CHK PUBLIC KEY", keyb64)
	shared.ExitOnError(err, "Unable to decode base64 public key data")

	pke, err := fsgo.CHKPKEImportPubkey(pubkey)
	shared.ExitOnError(err, "Error parsing public key")

	if len(*filepath) == 0 {
		input, err = ioutil.ReadAll(os.Stdin)
		shared.ExitOnError(err, "Error reading input from stdin")
	} else {
		input, err = ioutil.ReadFile(*filepath)
		shared.ExitOnError(err, "Error reading input from file")
	}

	e := pke.GenerateRandomElement()
	enckey, err := pke.Encrypt(e, *interval)
	shared.ExitOnError(err, "Error encrypting")

	chachakey := sha256.Sum256(e.ToBytes())

	if 12 != chacha20poly1305.NonceSize {
		os.Stderr.WriteString("Error: nonce size mismatch")
		os.Exit(1)
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	_, err = rand.Read(nonce)
	shared.ExitOnError(err, "error reading random nonce data")

	var msg shared.CHKMessage

	msg.AD.Enckey = enckey
	msg.AD.Nonce = nonce
	msg.AD.Interval = *interval

	ad, err := msg.AD.ToDER()
	shared.ExitOnError(err, "Error encoding additional data to DER")

	cipher, err := chacha20poly1305.New(chachakey[:])
	shared.ExitOnError(err, "Error creating symmetric cipher")

	msg.CT = cipher.Seal(nil, nonce, input, ad)

	msgDER, err := msg.ToDER()
	shared.ExitOnError(err, "Error encoding message+AD to DER")

	shared.WriteB64Wrapped("CHK ENCRYPTED MESSAGE", msgDER)
}
