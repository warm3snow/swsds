package swsds

import (
	"crypto/ecdsa"
	"math/big"
	"unsafe"
)

type Crypto interface {

	//device operations
	OpenDevice()
	CloseDevice()
	OpenSession() (unsafe.Pointer, error)
	CloseSession(ssHandle unsafe.Pointer)

	//SM2 keyGen, sign and verify
	SM2_GenKeyPair(ssHandle unsafe.Pointer) (*ecdsa.PrivateKey, error)
	SM2_Sign(ssHandle unsafe.Pointer, priv *ecdsa.PrivateKey, hash []byte) (r, s *big.Int, err error)
	SM2_Verify(ssHandle unsafe.Pointer, pub *ecdsa.PublicKey, hash []byte, r, s *big.Int) (bool, error)

	//hash, hmac algo
	SM3_Hash(ssHandle unsafe.Pointer, msg []byte) ([]byte, error)
	SM3_HashInit(handle unsafe.Pointer) error
	SM3_HashUpdate(ssHandle unsafe.Pointer, msg []byte) error
	SM3_HashFinal(ssHandle unsafe.Pointer) ([]byte, error)
	SM3_hmac(handle unsafe.Pointer, key, msg []byte) ([]byte, error)

	/*
		//SM2_MultAdd C = (d_k + e)A + B
		SM2_MultAdd(handle unsafe.Pointer, k uint32, e *ecdsa.PrivateKey, a, b *ecdsa.PublicKey) (*ecdsa.PublicKey, error)
		//SM2_ModMultAdd C = (kA + B) Mod n
		SM2_ModMultAdd(handle unsafe.Pointer, k, a, b *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error)
	*/
	//SM2_MultAdd C = eA + B
	SM2_MultAdd(handle unsafe.Pointer, e *ecdsa.PrivateKey, a, b *ecdsa.PublicKey) (*ecdsa.PublicKey, error)
	//SM2_ModMultAdd C = (A + B) Mod n
	SM2_ModMultAdd(handle unsafe.Pointer, a, b *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error)

	//SM4_crypt_enc  use ECB
	SM4_crypt_enc(key, msg []byte) ([]byte, error)
	SM4_crypt_dec(key, msg []byte) ([]byte, error)
}
