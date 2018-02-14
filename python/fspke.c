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

#include <fspke.h>
#include <Python.h>
#include <structmember.h>

PyDoc_STRVAR(CHKPKE__doc__,
"CHK Forward Secure Public Key Encryption (CHKPKE)\n\n\
CHKPKE implements a cryptosystem based on the Canetti, Halevi and Katz\n\
model as defined in \"A Forward-Secure Public-Key Encryption Scheme\",\n\
published in Eurocrypt2003, archived (https://eprint.iacr.org/2003/083).\n\
This asymmetric encryption model enables encryption of data based on a\n\
static public key and a defined set of intervals. The private key has\n\
the ability to evolve over time to \"forget\" the ability to decrypt\n\
messages from previous intervals (forward security) such that messages\n\
from previous intervals cannot be decrypted if the revised (pruned) public\n\
key is divulged.\n\n\
The Canetti-Halevi-Katz scheme uses symmetric pairings of Elliptic\n\
Curves (ECs), G1 X G1 -> G2, where elements in G1 are EC points and\n\
elements in G2 are curve points in Fp2 (F-p-squared). Messages (M) are\n\
in Fp2. Ciphertexts include multiple EC points and an element in Fp2.\n\
The Public Key includes parameters of the curves, pairing and a universal\n\
hash function.\n\n\
NOTE: This implementation forgoes the optimization (see Section 3.3) of\n\
using every node of the tree and instead only uses leaf nodes such that\n\
a constant ciphertext size is maintained. This optimization does not\n\
affect the security proofs provided by Canetti, Halevi and Katz and with\n\
larger btree orders the cost in storage is negligible.\n");

// allocate the object
static PyObject *CHKPKE_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	// create the new Parameterss object
	CHKPKE *self = (CHKPKE *)type->tp_alloc(type, 0);
	self->ready = 0;
	// make sure it actually worked
	if (!self) {
		PyErr_SetString(PyExc_TypeError, "could not create CHKPKE object.");
		return NULL;
	}

	// cast and return
	return (PyObject *)self;
}

// Usage options:
// CHKPKE(qbits=long, rbits=long, depth=long, order=long)
// CHKPKE(privkey=bytes)
// CHKPKE(pubkey=bytes)
static int CHKPKE_init(CHKPKE *self, PyObject *args, PyObject *kwargs) {
	char *kwds[] = {"qbits", "rbits", "depth", "order", "privkey",
	                "pubkey", NULL};
	// generate a new cryptosystem (need all parameters)
	int qbits = 512;
	int rbits = 384;
	int depth = 6;
	int order = 16;
	// create and import from ASN1 DER (bytes type)
	char *privkey_string = NULL;
	int privkey_len = 0;
	char *pubkey_string = NULL;
	int pubkey_len = 0;

	int status;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|iiiiy#y#", kwds,
		&qbits, &rbits, &depth, &order, &privkey_string, &privkey_len,
		&pubkey_string, &pubkey_len)) {
		PyErr_SetString(PyExc_TypeError, "Error parsing CHKPKE_init arguments");
		return -1;
	}

    // three basic patterns for init: Gen new, privkey, import pubkey
    // privkey specified
    if (privkey_string != NULL) {
        if (pubkey_string != NULL) {
    		PyErr_SetString(PyExc_ValueError, "Error: cannot specify both private and public keys");
    		return -1;
        }
        if (privkey_len <= 0) {
    		PyErr_SetString(PyExc_ValueError, "Error: privkey bytes of len 0 not valid");
    		return -1;
        }

        // import ASN1 DER binary as a privkey
        status = CHKPKE_init_privkey_decode_DER(self->pke, privkey_string, privkey_len);
        if (status != 0) {
    		PyErr_SetString(PyExc_ValueError, "Error: error parsing privkey as ASN1 DER string");
    		return -1;
        }
    } else if (pubkey_string != NULL) {
        if (pubkey_len <= 0) {
    		PyErr_SetString(PyExc_ValueError, "Error: privkey bytes of len 0 not valid");
    		return -1;
        }

        // import ASN1 DER binary as a pubkey
        status = CHKPKE_init_pubkey_decode_DER(self->pke, pubkey_string, pubkey_len);
        if (status != 0) {
    		PyErr_SetString(PyExc_ValueError, "Error: error parsing pubkey as ASN1 DER string");
    		return -1;
        }
    } else {
        if ((qbits <= 0) || (rbits <= 0) || (depth < 1) || (order < 2) || (qbits < (rbits + 4))) {
    		PyErr_SetString(PyExc_ValueError, "Error: invalid Gen parameters");
    		return -1;
        }

        // Initialize/Generate new PKE system (randomized, sized based on parameters)
        CHKPKE_init_Gen(self->pke, qbits, rbits, depth, order);
    }

	// you're ready!
	self->ready = 1;
	// all's clear
	return 0;
}

// deallocates the object when done
static void CHKPKE_dealloc(CHKPKE *self) {
	// clear the internal element
	if (self->ready){
		CHKPKE_clear(self->pke);
	}

	// free the object
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *CHKPKE_pubkey_encode(CHKPKE *self, PyObject *args) {
    char *der;
    int len;
    PyObject *bytes;

    der = CHKPKE_pubkey_encode_DER(self->pke, &len);
    bytes = PyBytes_FromStringAndSize(der, len);
    free(der);
    return bytes;
}

static PyObject *CHKPKE_privkey_encode(CHKPKE *self, PyObject *args, PyObject *kwargs) {
	char *keys[] = {"start", "end", NULL};
    int64_t start = 0;
    int64_t end = -1;
    char *der;
    int len;
    PyObject *bytes;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "|LL", keys, &start, &end)) {
		PyErr_SetString(PyExc_TypeError, "Error parsing CHKPKE_privkey_encode arguments");
		return NULL;
	}

    // basic input validation - if end > order ** depth, that will be caught below
    if ((start < 0) || ((end >= 0) && (end < start))) {
    		PyErr_SetString(PyExc_ValueError, "Error: invalid start/end interval");
    		return NULL;
    }

    if (end < start) {
        der = CHKPKE_privkey_encode_DER(self->pke, start, &len);
    } else {
        der = CHKPKE_privkey_encode_delegate_DER(self->pke, start, end, &len);
    }

    if (der == NULL) {
		PyErr_SetString(PyExc_ValueError, "Error: ucannot derive key for range");
		return NULL;
    }

    bytes = PyBytes_FromStringAndSize(der, len);
    free(der);
    return bytes;
}

static PyObject *CHKPKE_encrypt(CHKPKE *self, PyObject *args, PyObject *kwargs) {
	char *keys[] = {"element", "interval", NULL};
    int64_t interval = -1;
    char *der;
    int len;
    PyObject *bytes;
    PyObject *element;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OL", keys, &element, &interval)) {
		PyErr_SetString(PyExc_TypeError, "Error parsing CHKPKE_encrypt arguments");
		return NULL;
	}

	// validate that we got a CHKPKE PyObject as input
	if(!PyObject_TypeCheck(element, &ElementType)) {
		PyErr_SetString(PyExc_TypeError, "Argument 1: expected Element, got something else.");
		return NULL;
	}

    // basic input validation
    if (interval < 0) {
    		PyErr_SetString(PyExc_ValueError, "Error: interval");
    		return NULL;
    }

    der = CHKPKE_Enc_DER(self->pke, ((CHKPKE_Element*)element)->e, interval, &len);

    if (der == NULL) {
		PyErr_SetString(PyExc_ValueError, "Error: ucannot derive key for range");
		return NULL;
    }

    bytes = PyBytes_FromStringAndSize(der, len);
    free(der);
    return bytes;
}

static PyObject *CHKPKE_decrypt(CHKPKE *self, PyObject *args, PyObject *kwargs) {
	char *keys[] = {"ciphertext", "interval", NULL};
    int64_t interval = -1;
    char *der;
    int len;
    int status;
    CHKPKE_Element *element;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y#L", keys, &der, &len, &interval)) {
		PyErr_SetString(PyExc_TypeError, "Error parsing CHKPKE_decrypt arguments");
		return NULL;
	}

    // basic input validation
    if ((len <= 0) || (interval < 0)) {
    		PyErr_SetString(PyExc_ValueError, "Error: bytes object invalid");
    		return NULL;
    }

    element = (CHKPKE_Element *)ElementType.tp_alloc(&ElementType, 0);
    Py_INCREF(self);
    element->pke_ptr = self;
    element_init_GT(element->e, self->pke->pairing);
    element->ready = 1;
    status = CHKPKE_Dec_DER(element->e, self->pke, der, len, interval);

    if (status != 0) {
		PyErr_SetString(PyExc_ValueError, "Error: cannot decrypt for interval");
		ElementType.tp_dealloc((PyObject *)element);
		return NULL;
    }

    return (PyObject *)element;
}

static PyMemberDef CHKPKE_members[] = {
	{NULL}
};

static PyMethodDef CHKPKE_methods[] = {
	//{"apply", Pairing_apply, METH_VARARGS, "applies the pairing."},
	{"pubkey", (PyCFunction)CHKPKE_pubkey_encode, METH_NOARGS, "exports the public key in ASN1 DER as bytes."},
	{"privkey", (PyCFunction)CHKPKE_privkey_encode, METH_VARARGS | METH_KEYWORDS, "exports the private key in ASN1 DER as bytes based on start and optional end intervals."},
	{"encrypt", (PyCFunction)CHKPKE_encrypt, METH_VARARGS | METH_KEYWORDS, "encrypts an element, return ciphertext in ASN1 DER (bytes), inputs are element, interval"},
	{"decrypt", (PyCFunction)CHKPKE_decrypt, METH_VARARGS | METH_KEYWORDS, "decrypts an element, returns ElementType, inputs are ASN1 DER (bytes), interval"},
	{NULL}
};

PyTypeObject CHKPKEType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"FSPKE.CHKPKE",                     /*tp_name*/
	sizeof(CHKPKE),                     /*tp_basicsize*/
	0,                                  /*tp_itemsize*/
	(destructor)CHKPKE_dealloc,         /*tp_dealloc*/
	0,                                  /*tp_print*/
	0,                                  /*tp_getattr*/
	0,                                  /*tp_setattr*/
	0,			                        /*tp_reserved*/
	0,                                  /*tp_repr*/
	0,                                  /*tp_as_number*/
	0,                                  /*tp_as_sequence*/
	0,                                  /*tp_as_mapping*/
	0,                                  /*tp_hash */
	0,                                  /*tp_call*/
	0,                                  /*tp_str*/
	0,                                  /*tp_getattro*/
	0,                                  /*tp_setattro*/
	0,                                  /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
	CHKPKE__doc__,                      /* tp_doc */
	0,		                            /* tp_traverse */
	0,		                            /* tp_clear */
	0,		                            /* tp_richcompare */
	0,		                            /* tp_weaklistoffset */
	0,		                            /* tp_iter */
	0,		                            /* tp_iternext */
	CHKPKE_methods,                     /* tp_methods */
	CHKPKE_members,                     /* tp_members */
	0,                                  /* tp_getset */
	0,                                  /* tp_base */
	0,                                  /* tp_dict */
	0,                                  /* tp_descr_get */
	0,                                  /* tp_descr_set */
	0,                                  /* tp_dictoffset */
	(initproc)CHKPKE_init,              /* tp_init */
	0,                                  /* tp_alloc */
	CHKPKE_new,                         /* tp_new */
};

PyDoc_STRVAR(Element__doc__,
"Element is a wrapper for Element_GT objects from the underlying Stanford\n\
Pairing Based Cryptography (PBC) library. It is represented here in a simple\n\
interface to facilitate only the limited usage required for FSPKE.\n");

// allocate the object
static PyObject *Element_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
	// create the new Parameterss object
	CHKPKE_Element *self = (CHKPKE_Element *)type->tp_alloc(type, 0);
	self->ready = 0;
	self->pke_ptr = NULL;
	// make sure it actually worked
	if (!self) {
		PyErr_SetString(PyExc_TypeError, "could not create Element object.");
		return NULL;
	}

	// cast and return
	return (PyObject *)self;
}

// Usage options:
// Element(PyObject(CHKPKEType))
static int Element_init(CHKPKE_Element *self, PyObject *args, PyObject *kwargs) {
	char *keys[] = {"chkpke", "bytes", NULL};
	// Link to underlying CHKPKE object
	PyObject *pkeObj = Py_None;
	char *b = NULL;
	int len;

	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O|y#", keys, &pkeObj, &b, &len)) {
		PyErr_SetString(PyExc_TypeError, "Error parsing Element_init arguments");
		return -1;
	}

	// validate that we got a CHKPKE PyObject as input
	if(!PyObject_TypeCheck(pkeObj, &CHKPKEType)) {
		PyErr_SetString(PyExc_TypeError, "Argument 1: expected CHKPKE, got something else.");
		return -1;
	}

    // attach to pkeObj
    Py_INCREF(pkeObj);
    self->pke_ptr = (CHKPKE*)pkeObj;

    // initialize element in pairing group (Fp2)
    element_init_GT(self->e, self->pke_ptr->pke->pairing);

    if (b != NULL) {
        int l;
        l = element_length_in_bytes(self->pke_ptr->pke->ePQ);

    	if(l != len) {
    		PyErr_SetString(PyExc_TypeError, "Argument 2: bytes object length mismatch.");
    		return -1;
    	}

        len = element_from_bytes(self->e, (unsigned char*)b);
        assert(l == len);
    }

	// you're ready!
	self->ready = 1;
	// all's clear
	return 0;
}

// deallocates the object when done
void Element_dealloc(CHKPKE_Element *self) {
	// clear the internal element
	if (self->ready){
		element_clear(self->e);

        // detach from pkeObj
        Py_DECREF(self->pke_ptr);
	}

	// free the object
	Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *Element_to_bytes(CHKPKE_Element *self, PyObject *args) {
    char *b;
    int len;
    PyObject *bytes;

    b = (char *)CHKPKE_element_to_bytes(self->e, &len);
    bytes = PyBytes_FromStringAndSize(b, len);
    free(b);
    return bytes;
}

static PyObject *Element_random(CHKPKE_Element *self, PyObject *args) {
    element_random(self->e);
    Py_INCREF(self);
    return (PyObject *)self;
}

static PyMemberDef Element_members[] = {
	{NULL}
};

static PyMethodDef Element_methods[] = {
	//{"apply", Pairing_apply, METH_VARARGS, "applies the pairing."},
	{"to_bytes", (PyCFunction)Element_to_bytes, METH_NOARGS, "export bytes value of element."},
	{"random", (PyCFunction)Element_random, METH_NOARGS, "set the value of the element based on input from /dev/urandom."},
	{NULL}
};

PyTypeObject ElementType = {
	PyVarObject_HEAD_INIT(NULL, 0)
	"FSPKE.Element",                     /*tp_name*/
	sizeof(CHKPKE_Element),                     /*tp_basicsize*/
	0,                                  /*tp_itemsize*/
	(destructor)Element_dealloc,         /*tp_dealloc*/
	0,                                  /*tp_print*/
	0,                                  /*tp_getattr*/
	0,                                  /*tp_setattr*/
	0,			                        /*tp_reserved*/
	0,                                  /*tp_repr*/
	0,                                  /*tp_as_number*/
	0,                                  /*tp_as_sequence*/
	0,                                  /*tp_as_mapping*/
	0,                                  /*tp_hash */
	0,                                  /*tp_call*/
	0,                                  /*tp_str*/
	0,                                  /*tp_getattro*/
	0,                                  /*tp_setattro*/
	0,                                  /*tp_as_buffer*/
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
	Element__doc__,                      /* tp_doc */
	0,		                            /* tp_traverse */
	0,		                            /* tp_clear */
	0,		                            /* tp_richcompare */
	0,		                            /* tp_weaklistoffset */
	0,		                            /* tp_iter */
	0,		                            /* tp_iternext */
	Element_methods,                     /* tp_methods */
	Element_members,                     /* tp_members */
	0,                                  /* tp_getset */
	0,                                  /* tp_base */
	0,                                  /* tp_dict */
	0,                                  /* tp_descr_get */
	0,                                  /* tp_descr_set */
	0,                                  /* tp_dictoffset */
	(initproc)Element_init,              /* tp_init */
	0,                                  /* tp_alloc */
	Element_new,                         /* tp_new */
};

//
// Module Implementation
//

// Module Global Methods
static PyMethodDef FSPKE_methods[] = {
	//{"get_random_prime", get_random_prime, METH_VARARGS, "get a random n-bit prime"},
	{NULL, NULL, 0, NULL}
};

static PyModuleDef FSPKE_module = {
	PyModuleDef_HEAD_INIT,
	"FSPKE",
	"FSPKE",
	-1,
	FSPKE_methods
};

PyMODINIT_FUNC
PyInit_FSPKE(void) 
{
	PyObject* m;

	if (PyType_Ready(&CHKPKEType) < 0)
		return NULL;

	if (PyType_Ready(&ElementType) < 0)
		return NULL;

	m = PyModule_Create(&FSPKE_module);

	if (m == NULL)
		return NULL;

	Py_INCREF(&CHKPKEType);
	Py_INCREF(&ElementType);
	// add the objects
	PyModule_AddObject(m, "CHKPKE", (PyObject *)&CHKPKEType);
	PyModule_AddObject(m, "Element", (PyObject *)&ElementType);
	return m;
}
