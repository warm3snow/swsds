/*encapsalute sansec api in golang*/
package swsds

//#cgo LDFLAGS: -L ./ -lswsds
//#include "./swsds.h"
import "C"

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"unsafe"
)

type swcsp struct {
	hDev unsafe.Pointer
}

func NewSwcsp() *swcsp {
	var hDeviceHandle C.SGD_HANDLE
	rv := C.SDF_OpenDevice(&hDeviceHandle)
	if rv != C.SDR_OK {
		log.Panicf("OpenDevice fail, rv=%#X\n", rv)
	}
	hDevHdl := unsafe.Pointer(hDeviceHandle)
	return &swcsp{hDev: hDevHdl}
}

func (t *swcsp) CloseDevice() {
	hDeviceHandle := C.SGD_HANDLE(t.hDev)
	rv := C.SDF_CloseDevice(hDeviceHandle)
	if rv != C.SDR_OK {
		log.Panicf("CloseDevice fail, rv =%#X\n", rv)
	}
}

func (t *swcsp) OpenSession() (unsafe.Pointer, error) {
	var hSessionHandle C.SGD_HANDLE
	rv := C.SDF_OpenSession(t.hDev, &hSessionHandle)
	if rv != C.SDR_OK {
		return nil, fmt.Errorf("OpenSession fail, rv=%#X\n", rv)
	}
	return unsafe.Pointer(hSessionHandle), nil
}

func (t *swcsp) CloseSession(ssHandle unsafe.Pointer) {
	hSessionHandle := C.SGD_HANDLE(ssHandle)
	rv := C.SDF_CloseSession(hSessionHandle)
	if rv != C.SDR_OK {
		log.Panicf("OpenSession fail, rv=%#X\n", rv)
	}
}

func (t *swcsp) SM2_GenKeyPair(ssHandle unsafe.Pointer) (*ecdsa.PrivateKey, error) {
	var rv C.SGD_RV
	var keyLen C.SGD_UINT32 = 256
	var pubKey C.struct_ECCrefPublicKey_st
	var priKey C.struct_ECCrefPrivateKey_st
	hSessionHandle := C.SGD_HANDLE(ssHandle)

	rv = C.SDF_GenerateKeyPair_ECC(hSessionHandle, C.SGD_SM2_3, keyLen, &pubKey, &priKey)
	if rv != C.SDR_OK {
		return nil, fmt.Errorf("GenKeyPair fails, rv = %#X\n", rv)
	}

	priv := new(ecdsa.PrivateKey)

	priv.D = new(big.Int).SetBytes(UcharArrToByteArr(priKey.D[:]))
	priv.PublicKey.X = new(big.Int).SetBytes(UcharArrToByteArr(pubKey.x[:]))
	priv.PublicKey.Y = new(big.Int).SetBytes(UcharArrToByteArr(pubKey.y[:]))

	return priv, nil
}

func (t *swcsp) SM2_Sign(ssHandle unsafe.Pointer, priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error) {
	var rv C.SGD_RV
	var priKey C.struct_ECCrefPrivateKey_st
	var signature C.struct_ECCSignature_st

	//inData length must be 32bytes, see ByteArrToSGD_UCHARArr
	inData := ByteArrToSGD_UCHARArr(hash)
	var inLen C.SGD_UINT32 = 32
	hSessionHandle := C.SGD_HANDLE(ssHandle)
	/*
		rv = C.SDF_GenerateRandom(hSessionHandle, inLen, &inData[0])
		if rv != C.SDR_OK {
			fmt.Printf("gen random fail, rv = %x\n", rv)
		}
	*/
	priKey.bits = 256
	copy(priKey.D[:], ByteArrToUcharArr(priv.D.Bytes()))

	rv = C.SDF_ExternalSign_ECC(hSessionHandle, C.SGD_SM2_1, &priKey, &inData[0], inLen, &signature)
	if rv != C.SDR_OK {
		return nil, nil, fmt.Errorf("SM2_ExternalSign fail, rv = %#X\n", rv)
	}

	r, s = new(big.Int), new(big.Int)
	r.SetBytes(UcharArrToByteArr(signature.r[:]))
	s.SetBytes(UcharArrToByteArr(signature.s[:]))

	return r, s, nil
}

func (t *swcsp) SM2_Verify(ssHandle unsafe.Pointer, pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) (bool, error) {
	var rv C.SGD_RV
	var pubKey C.struct_ECCrefPublicKey_st
	var signature C.struct_ECCSignature_st
	var inLen C.SGD_UINT32
	hSessionHandle := C.SGD_HANDLE(ssHandle)

	//inData length must be 32bytes, see ByteArrToSGD_UCHARArr
	inData := ByteArrToSGD_UCHARArr(hash)
	inLen = 32
	copy(pubKey.x[:], ByteArrToUcharArr(pub.X.Bytes()))
	copy(pubKey.y[:], ByteArrToUcharArr(pub.Y.Bytes()))
	pubKey.bits = 256
	copy(signature.r[:], ByteArrToUcharArr(r.Bytes()))
	copy(signature.s[:], ByteArrToUcharArr(s.Bytes()))

	rv = C.SDF_ExternalVerify_ECC(hSessionHandle, C.SGD_SM2_1, &pubKey, &inData[0], inLen, &signature)

	fmt.Println()
	if rv != C.SDR_OK {
		return false, fmt.Errorf("SM2_Verify fails, rv = %#X\n", rv)
	}

	return true, nil
}

func (t *swcsp) SM3_Hash(ssHandle unsafe.Pointer, msg []byte) ([]byte, error) {
	hSessionHandle := C.SGD_HANDLE(ssHandle)
	var rv C.SGD_RV
	var outData [128]C.SGD_UCHAR
	var inLen, outLen C.SGD_UINT32

	inData := ByteArrToSGD_UCHARArr(msg)
	inLen = C.SGD_UINT32(len(msg))

	rv = C.SDF_HashInit(hSessionHandle, C.SGD_SM3, nil, nil, 0)
	if rv == C.SDR_OK {
		rv = C.SDF_HashUpdate(hSessionHandle, &inData[0], inLen)
		if rv == C.SDR_OK {
			C.SDF_HashFinal(hSessionHandle, &outData[0], &outLen)
			if rv != C.SDR_OK {
				return nil, fmt.Errorf("SM3_HashFinal fail, rv=%#X\n", rv)
			}
		}
	} else {
		return nil, fmt.Errorf("SM3_Hash fail, rv=%#X\n", rv)
	}
	return SGD_UCHARArrToByteArr(outData[:outLen]), nil
}

func (t *swcsp) SM3_HashInit(handle unsafe.Pointer) error {
	hSessionHandle := C.SGD_HANDLE(handle)
	var rv C.SGD_RV

	rv = C.SDF_HashInit(hSessionHandle, C.SGD_SM3, nil, nil, 0)
	if rv == C.SDR_OK {
		return fmt.Errorf("SM3_HashFinal fail, rv=%#X\n", rv)
	}
	return nil
}
func (t *swcsp) SM3_HashUpdate(ssHandle unsafe.Pointer, msg []byte) error {
	hSessionHandle := C.SGD_HANDLE(ssHandle)
	var rv C.SGD_RV
	var inLen C.SGD_UINT32

	inData := ByteArrToSGD_UCHARArr(msg)
	inLen = C.SGD_UINT32(len(msg))

	rv = C.SDF_HashUpdate(hSessionHandle, &inData[0], inLen)
	if rv == C.SDR_OK {
		return fmt.Errorf("SM3_HashFinal fail, rv=%#X\n", rv)
	}
	return nil
}
func (t *swcsp) SM3_HashFinal(ssHandle unsafe.Pointer) ([]byte, error) {
	hSessionHandle := C.SGD_HANDLE(ssHandle)
	var rv C.SGD_RV
	var outData [128]C.SGD_UCHAR
	var outLen C.SGD_UINT32

	rv = C.SDF_HashFinal(hSessionHandle, &outData[0], &outLen)
	if rv != C.SDR_OK {
		return nil, fmt.Errorf("SM3_HashFinal fail, rv=%#X\n", rv)
	}
	return SGD_UCHARArrToByteArr(outData[:outLen]), nil
}

func (t *swcsp) SM3_hmac(handle unsafe.Pointer, key, msg []byte) ([]byte, error) {
	blkLen := 64
	var relKey []byte
	if len(key) > 64 {
		relKey, _ = t.SM3_Hash(handle, key)
	}
	copy(relKey, key)

	var ipad, opad []byte
	for i := 0; i < blkLen; i++ {
		if i < len(relKey) {
			ipad = append(ipad, relKey[i])
			opad = append(opad, relKey[i])
		} else {
			ipad = append(ipad, []byte("0")[0])
			opad = append(opad, []byte("0")[0])
		}
	}

	for i := 0; i < blkLen; i++ {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}
	t.SM3_HashInit(handle)
	t.SM3_HashUpdate(handle, ipad)
	t.SM3_HashUpdate(handle, msg)
	tmpHsh, _ := t.SM3_HashFinal(handle)

	t.SM3_HashInit(handle)
	t.SM3_HashUpdate(handle, opad)
	t.SM3_HashUpdate(handle, tmpHsh)
	fnlHsh, _ := t.SM3_HashFinal(handle)

	return fnlHsh, nil

}

/* util funcs */
func UcharArrToByteArr(buf []C.uchar) []byte {
	var ret []byte
	for i := 0; i < len(buf); i++ {
		ret = append(ret, byte(buf[i]))
	}
	return ret
}
func ByteArrToUcharArr(buf []byte) []C.uchar {
	var ret []C.uchar
	for i := 0; i < 32; i++ {
		if i < len(buf) {
			ret = append(ret, C.uchar(buf[i]))
		} else {
			ret = append(ret, C.uchar([]byte("0")[0]))
		}
	}
	return ret
}
func ByteArrToSGD_UCHARArr(buf []byte) []C.SGD_UCHAR {
	var ret []C.SGD_UCHAR
	for i := 0; i < 32; i++ {
		if i < len(buf) {
			ret = append(ret, C.SGD_UCHAR(buf[i]))
		} else {
			ret = append(ret, C.SGD_UCHAR([]byte("0")[0]))
		}
	}
	return ret
}
func SGD_UCHARArrToByteArr(buf []C.SGD_UCHAR) []byte {
	var ret []byte
	for i := 0; i < len(buf); i++ {
		ret = append(ret, byte(buf[i]))
	}
	return ret
}
