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

// #cgo CFLAGS: -I/usr/local/include/pbc -I/usr/include/pbc
// #cgo LDFLAGS: -lfspke
// #include <chkpke.h>
// #include <pbc.h>
// #include <stdlib.h>
//
// _CHKPKE_t *malloc_CHKPKE() {
//     return (_CHKPKE_t *)malloc(sizeof(_CHKPKE_t));
// }
//
// void free_CHKPKE(_CHKPKE_t *pke) {
//     free(pke);
// }
//
// element_ptr malloc_Element() {
//     return (element_ptr)malloc(sizeof(struct element_s));
// }
//
// void free_Element(element_ptr e) {
//     free(e);
// }
//
// char *unsafeptr_to_charptr(void *in) {
//     return (char *)in;
// }
//
// int range_cmp_interval(_CHKPKE_t *pke, int64_t interval) {
//     if (interval < 0) return -1;
//     if (interval > pke->maxinterval) return 1;
//     return 0;
// }
//
import "C"

import (
	//"bytes"
	//"encoding/base64"
	//"encoding/hex"
	//"encoding/binary"
	"errors"
	//"fmt"
	//"io/ioutil"
	//"os"
	//"reflect"
	"runtime"
	//"strconv"
	//"strings"
	//"time"
	"unsafe"
)

type CHKPKE struct {
	pke *C._CHKPKE_t
}

type Element struct {
	ele  C.element_ptr
	gpke *CHKPKE
}

func CHKPKEGen(qbits, rbits, depth, order int) (z *CHKPKE) {
	z = new(CHKPKE)
	z.pke = C.malloc_CHKPKE()
	C.CHKPKE_init_Gen(z.pke, C.int(qbits), C.int(rbits), C.int(depth), C.int(order))
	runtime.SetFinalizer(z, chkpke_clear)
	return z
}

func chkpke_clear(z *CHKPKE) {
	C.CHKPKE_clear(z.pke)
	C.free_CHKPKE(z.pke)
}

func (z *CHKPKE) ExportPubkey() (key []byte, err error) {
	//var pke *C._CHKPKE_t
	var der *C.char
	l := C.int(0)

	der, _ = C.CHKPKE_pubkey_encode_DER(z.pke, &l)
	if der == nil {
		return nil, errors.New("CHKPKE.ExportPubkey: Unable to export pubkey")
	}

	defer C.free(unsafe.Pointer(der))
	return C.GoBytes(unsafe.Pointer(der), l), nil
}

func (z *CHKPKE) ExportPrivkey(start int64) (key []byte, err error) {
	//var pke *C._CHKPKE_t
	var der *C.char
	l := C.int(0)
	st := C.int64_t(start)

	der = C.CHKPKE_privkey_encode_DER(z.pke, st, &l)
	if der == nil {
		return nil, errors.New("CHKPKE.ExportPrivkey: Unable to export privkey")
	}

	defer C.free(unsafe.Pointer(der))
	return C.GoBytes(unsafe.Pointer(der), l), nil
}

func (z *CHKPKE) ExportDelegatePrivkey(start, end int64) (key []byte, err error) {
	//var pke *C._CHKPKE_t
	var der *C.char
	l := C.int(0)
	st := C.int64_t(start)
	en := C.int64_t(end)

	der = C.CHKPKE_privkey_encode_delegate_DER(z.pke, st, en, &l)
	if der == nil {
		return nil, errors.New("CHKPKE.ExportDelegatePrivkey: Unable to export privkey")
	}

	defer C.free(unsafe.Pointer(der))
	return C.GoBytes(unsafe.Pointer(der), l), nil
}

func CHKPKEImportPubkey(key []byte) (z *CHKPKE, err error) {
	z = new(CHKPKE)
	z.pke = C.malloc_CHKPKE()
	r := C.CHKPKE_init_pubkey_decode_DER(z.pke, C.unsafeptr_to_charptr(C.CBytes(key)), C.int(len(key)))
	if r != C.int(0) {
		C.free_CHKPKE(z.pke)
		return nil, errors.New("ImportPubkey: decode DER failed")
	}
	runtime.SetFinalizer(z, chkpke_clear)
	return z, nil
}

func CHKPKEImportPrivkey(key []byte) (z *CHKPKE, err error) {
	z = new(CHKPKE)
	z.pke = C.malloc_CHKPKE()
	r := C.CHKPKE_init_privkey_decode_DER(z.pke, C.unsafeptr_to_charptr(C.CBytes(key)), C.int(len(key)))
	if r != C.int(0) {
		C.free_CHKPKE(z.pke)
		return nil, errors.New("ImportPubkey: decode DER failed")
	}
	runtime.SetFinalizer(z, chkpke_clear)
	return z, nil
}

func element_clear(e *Element) {
	C.element_clear(e.ele)
	C.free_Element(e.ele)
}

func (z *CHKPKE) GenerateRandomElement() (e *Element) {
	e = new(Element)
	e.ele = C.malloc_Element()
	C.CHKPKE_init_random_element(e.ele, z.pke)
	runtime.SetFinalizer(e, element_clear)
	return e
}

func (e *Element) ToBytes() (b []byte) {
	var c_b *C.uchar
	l := C.int(0)

	c_b = C.CHKPKE_element_to_bytes(e.ele, &l)

	defer C.free(unsafe.Pointer(c_b))
	return C.GoBytes(unsafe.Pointer(c_b), l)
}

func (z *CHKPKE) Encrypt(e *Element, interval int64) (ct []byte, err error) {
	var c_ct *C.char
	l := C.int(0)
	c_interval := C.int64_t(interval)

	if C.range_cmp_interval(z.pke, c_interval) != C.int(0) {
		return nil, errors.New("CHKPKE.Encrypt: interval out of range")
	}

	c_ct = C.CHKPKE_Enc_DER(z.pke, e.ele, c_interval, &l)
	if c_ct == nil {
		panic("CHKPKE.Encrypt: Encryption failed; unexpected error condition")
	}

	defer C.free(unsafe.Pointer(c_ct))
	return C.GoBytes(unsafe.Pointer(c_ct), l), nil
}

func (z *CHKPKE) Decrypt(ct []byte, interval int64) (e *Element, err error) {
	e = new(Element)
	e.ele = C.malloc_Element()

	C.CHKPKE_init_element(e.ele, z.pke)
	status := C.CHKPKE_Dec_DER(e.ele, z.pke, C.unsafeptr_to_charptr(C.CBytes(ct)),
		C.int(len(ct)), C.int64_t(interval))
	if status != C.int(0) {
		C.CHKPKE_element_clear(e.ele)
		C.free_Element(e.ele)
		return nil, errors.New("CHKPKE.Decrypt: Unable to decrypt for interval")
	}
	return e, nil
}

func (z *CHKPKE) Maxinterval() int64 {
	return int64(z.pke.maxinterval)
}
