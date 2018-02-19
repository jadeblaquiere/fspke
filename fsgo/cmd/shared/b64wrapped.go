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

package shared

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

func ReadB64Wrapped(typeLabel string, in []byte) (out []byte, err error) {
	sdata := strings.Split(string(in[:]), "-----")
	l := len(sdata)
	slabel := fmt.Sprintf("BEGIN %s", typeLabel)
	elabel := fmt.Sprintf("END %s", typeLabel)
	for i := 0; i < (l - 2); i++ {
		if strings.Compare(sdata[i], slabel) == 0 {
			if strings.Compare(sdata[i+2], elabel) == 0 {
				payload, err := base64.StdEncoding.DecodeString(sdata[i+1])
				if err != nil {
					break
				}
				return payload, nil
			} else {
				break
			}
		}
	}
	return nil, errors.New("malformed wrapped base64 input")
}

func WriteB64Wrapped(typeLabel string, payload []byte) {
	fmt.Printf("-----BEGIN %s-----\n", typeLabel)
	fmt.Println(base64.StdEncoding.EncodeToString(payload))
	fmt.Printf("-----END %s-----\n", typeLabel)
}
