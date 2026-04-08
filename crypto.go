// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pdf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"math/big"
)

// EncryptionVersion represents PDF encryption version
type EncryptionVersion int

const (
	EncryptionV1 EncryptionVersion = 1 // RC4 40-bit
	EncryptionV2 EncryptionVersion = 2 // RC4 40-128-bit
	EncryptionV4 EncryptionVersion = 4 // RC4 or AES 128-bit
	EncryptionV5 EncryptionVersion = 5 // AES 256-bit
)

// EncryptionRevision represents PDF encryption revision
type EncryptionRevision int

const (
	Revision2 EncryptionRevision = 2 // MD5-based
	Revision3 EncryptionRevision = 3 // MD5-based with key strengthening
	Revision4 EncryptionRevision = 4 // MD5-based with access permissions
	Revision5 EncryptionRevision = 5 // SHA-256-based
	Revision6 EncryptionRevision = 6 // SHA-384/512-based
)

// EncryptionMethod represents the encryption method
type EncryptionMethod int

const (
	MethodRC4   EncryptionMethod = 0
	MethodAESV2 EncryptionMethod = 1 // AES-128 CBC
	MethodAESV3 EncryptionMethod = 2 // AES-256 CBC
)

var iv = make([]byte, aes.BlockSize)

// PDFEncryptionInfo contains encryption parameters
type PDFEncryptionInfo struct {
	Version   EncryptionVersion
	Revision  EncryptionRevision
	Method    EncryptionMethod
	KeyLength int    // in bits
	O         []byte // Owner password hash
	U         []byte // User password hash
	P         uint32 // Permissions
	ID        []byte // Document ID
	OE        []byte // Owner encryption key (V5)
	UE        []byte // User encryption key (V5)
	Perms     []byte // Encrypted permissions (V5)
}

// CryptoEngine provides encryption/decryption functionality
type CryptoEngine struct {
	info *PDFEncryptionInfo
	key  []byte
}

// NewCryptoEngine creates a new crypto engine
func NewCryptoEngine(info *PDFEncryptionInfo) *CryptoEngine {
	return &CryptoEngine{
		info: info,
	}
}

// SetKey sets the encryption key
func (e *CryptoEngine) SetKey(key []byte) {
	e.key = make([]byte, len(key))
	copy(e.key, key)
}

// EncryptData encrypts data using the current encryption method
func (e *CryptoEngine) EncryptData(data []byte, objID, genID int) ([]byte, error) {
	if e.key == nil {
		return data, nil
	}

	key := e.computeObjectKey(objID, genID)

	switch e.info.Method {
	case MethodRC4:
		return e.encryptRC4(data, key)
	case MethodAESV2, MethodAESV3:
		return e.encryptAES(data, key)
	default:
		return data, fmt.Errorf("unsupported encryption method: %d", e.info.Method)
	}
}

// DecryptData decrypts data using the current encryption method
func (e *CryptoEngine) DecryptData(data []byte, objID, genID int) ([]byte, error) {
	if e.key == nil {
		return data, nil
	}

	key := e.computeObjectKey(objID, genID)

	switch e.info.Method {
	case MethodRC4:
		return e.decryptRC4(data, key)
	case MethodAESV2, MethodAESV3:
		return e.decryptAES(data, key)
	default:
		return data, fmt.Errorf("unsupported encryption method: %d", e.info.Method)
	}
}

// computeObjectKey computes the object-specific encryption key
func (e *CryptoEngine) computeObjectKey(objID, genID int) []byte {
	h := md5.New()
	h.Write(e.key)
	h.Write([]byte{byte(objID), byte(objID >> 8), byte(objID >> 16)})
	h.Write([]byte{byte(genID), byte(genID >> 8)})

	if e.info.Method == MethodAESV2 || e.info.Method == MethodAESV3 {
		h.Write([]byte("sAlT"))
	}

	hash := h.Sum(nil)
	keyLen := len(e.key)
	if keyLen > 16 {
		keyLen = 16
	}
	return hash[:keyLen]
}

// encryptRC4 encrypts data using RC4
func (e *CryptoEngine) encryptRC4(data, key []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	result := make([]byte, len(data))
	c.XORKeyStream(result, data)
	return result, nil
}

// decryptRC4 decrypts data using RC4
func (e *CryptoEngine) decryptRC4(data, key []byte) ([]byte, error) {
	return e.encryptRC4(data, key) // RC4 is symmetric
}

// encryptAES encrypts data using AES-CBC
func (e *CryptoEngine) encryptAES(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Pad data to block size
	padded := e.padPKCS7(data, aes.BlockSize)

	// Encrypt
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)

	// Prepend IV
	result := make([]byte, len(iv)+len(ciphertext))
	copy(result, iv)
	copy(result[len(iv):], ciphertext)

	return result, nil
}

// decryptAES decrypts data using AES-CBC
func (e *CryptoEngine) decryptAES(data, key []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove padding
	plaintext, err = e.unpadPKCS7(plaintext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// padPKCS7 pads data using PKCS#7
func (e *CryptoEngine) padPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// unpadPKCS7 removes PKCS#7 padding
func (e *CryptoEngine) unpadPKCS7(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	padding := int(data[len(data)-1])
	if padding > len(data) || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}

	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padding], nil
}

// PasswordAuth authenticates a password using the appropriate algorithm
type PasswordAuth struct {
	info *PDFEncryptionInfo
}

// NewPasswordAuth creates a new password authenticator
func NewPasswordAuth(info *PDFEncryptionInfo) *PasswordAuth {
	return &PasswordAuth{info: info}
}

// Authenticate tries to authenticate with the given password as either user or owner
func (pa *PasswordAuth) Authenticate(password string) ([]byte, error) {
	// Try user password first
	if key, err := pa.AuthenticateUser(password); err == nil {
		return key, nil
	}
	// Try owner password
	return pa.AuthenticateOwner(password)
}

// AuthenticateOwner authenticates an owner password
func (pa *PasswordAuth) AuthenticateOwner(password string) ([]byte, error) {
	switch pa.info.Revision {
	case Revision2, Revision3, Revision4:
		return pa.authenticateOwnerR2R4(password)
	case Revision5:
		return pa.authenticateOwnerR5(password)
	case Revision6:
		return pa.authenticateOwnerR6(password)
	default:
		return nil, fmt.Errorf("unsupported encryption revision: %d", pa.info.Revision)
	}
}

// AuthenticateUser authenticates a user password
func (pa *PasswordAuth) AuthenticateUser(password string) ([]byte, error) {
	switch pa.info.Revision {
	case Revision2, Revision3, Revision4:
		return pa.authenticateUserR2R4(password)
	case Revision5:
		return pa.authenticateUserR5(password)
	case Revision6:
		return pa.authenticateUserR6(password)
	default:
		return nil, fmt.Errorf("unsupported encryption revision: %d", pa.info.Revision)
	}
}

// authenticateUserR2R4 implements user password authentication for R2-R4
func (pa *PasswordAuth) authenticateUserR2R4(password string) ([]byte, error) {
	pw := toLatin1(password)
	h := md5.New()

	if len(pw) >= 32 {
		h.Write(pw[:32])
	} else {
		h.Write(pw)
		h.Write(passwordPad[:32-len(pw)])
	}

	h.Write(pa.info.O)
	h.Write([]byte{byte(pa.info.P), byte(pa.info.P >> 8), byte(pa.info.P >> 16), byte(pa.info.P >> 24)})
	h.Write(pa.info.ID)

	key := h.Sum(nil)

	if pa.info.Revision >= Revision3 {
		for i := 0; i < 50; i++ {
			h.Reset()
			h.Write(key[:pa.info.KeyLength/8])
			key = h.Sum(key[:0])
		}
		key = key[:pa.info.KeyLength/8]
	} else {
		key = key[:40/8]
	}

	return key, nil
}

// authenticateOwnerR2R4 implements owner password authentication for R2-R4
func (pa *PasswordAuth) authenticateOwnerR2R4(password string) ([]byte, error) {
	return pa.authenticateUserR2R4(password) // Same algorithm for R2-R4
}

// authenticateUserR5 implements user password authentication for R5 (SHA-256)
func (pa *PasswordAuth) authenticateUserR5(password string) ([]byte, error) {
	pw := toLatin1(password)

	// Step 1: Compute hash of user password
	h := sha256.New()
	h.Write(pw)
	h.Write(pa.info.U[:8]) // First 8 bytes of U

	hash := h.Sum(nil)

	// Step 2: Use hash as key for AES-128 decryption of UE
	block, err := aes.NewCipher(hash[:16])
	if err != nil {
		return nil, err
	}

	if len(pa.info.UE)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid UE length: not full AES blocks")
	}
	ue := make([]byte, len(pa.info.UE))
	mode := newECBDecrypter(block)
	mode.CryptBlocks(ue, pa.info.UE)

	return ue[:32], nil // First 32 bytes are the key
}

// authenticateOwnerR5 implements owner password authentication for R5
func (pa *PasswordAuth) authenticateOwnerR5(password string) ([]byte, error) {
	pw := toLatin1(password)

	// Step 1: Compute hash of owner password
	h := sha256.New()
	h.Write(pw)
	h.Write(pa.info.O[:8]) // First 8 bytes of O
	h.Write(pa.info.UE)    // UE as salt

	hash := h.Sum(nil)

	// Step 2: Use hash as key for AES-128 decryption of OE
	block, err := aes.NewCipher(hash[:16])
	if err != nil {
		return nil, err
	}

	if len(pa.info.OE)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid OE length: not full AES blocks")
	}
	oe := make([]byte, len(pa.info.OE))
	mode := newECBDecrypter(block)
	mode.CryptBlocks(oe, pa.info.OE)

	return oe[:32], nil // First 32 bytes are the key
}

// authenticateUserR6 implements user password authentication for R6 (SHA-384/512)
func (pa *PasswordAuth) authenticateUserR6(password string) ([]byte, error) {
	// 2.A.a
	pw := []byte(password)
	// 2.A.b
	if len(pw) > 127 {
		pw = pw[:127]
	}

	// 2.A.c, 2.A.d is irrelevant in this func

	// 2.A.e
	h := sha256.New()
	h.Write(pw)
	h.Write(pa.info.U[40 : 40+8]) // key salt
	k0 := h.Sum(nil)
	k, err := pa.computeHashR6(password, k0, false)
	if err != nil {
		return nil, err
	}

	// 2.A.e
	block, _ := aes.NewCipher(k[:32])

	mode := cipher.NewCBCDecrypter(block, iv)
	fileKey := make([]byte, 32)
	mode.CryptBlocks(fileKey, pa.info.UE)

	if err := pa.validateFileKey(fileKey); err != nil {
		return nil, err
	}

	return fileKey, nil
}

// computeHashR6 implements 7.6.4.3.3 - Algorithm 2.B: Computing a hash (revision 6 and later)
func (pa *PasswordAuth) computeHashR6(password string, k0 []byte, owner bool) ([]byte, error) {
	var h hash.Hash
	k := k0

	for i := 0; ; i++ {
		// println("k", i, hex.EncodeToString(k))

		// 2.B.a
		base := append([]byte(password), k...)
		if owner {
			base = append(base, pa.info.U...)
		}
		sz := len(base)
		k1 := make([]byte, sz*64)
		for j := 0; j < 64; j++ {
			copy(k1[j*sz:(j+1)*sz], base)
		}

		// 2.B.b
		block, err := aes.NewCipher(k[:16])
		if err != nil {
			return nil, err
		}
		// println("iv =", hex.EncodeToString(k[16:32]))
		mode := cipher.NewCBCEncrypter(block, k[16:32])
		e := make([]byte, len(k1))
		mode.CryptBlocks(e, k1)
		// println("E", i, hex.EncodeToString(e[:16]), hex.EncodeToString(e[len(e)-16:]))
		// println(len(E))

		// 2.B.c
		val := new(big.Int).SetBytes(e[:16])
		mod := new(big.Int).Mod(val, big.NewInt(3)).Int64()
		// println("mod =", mod)
		switch mod {
		case 0:
			h = sha256.New()
		case 1:
			h = sha512.New384()
		case 2:
			h = sha512.New()
		}
		h.Write(e)

		// 2.B.d
		k = h.Sum(nil)[:]

		// 2.B.e-f
		if i >= 64 && int(e[len(e)-1]) <= i-32 {
			break
		}
	}
	return k, nil
}

func (pa *PasswordAuth) validateFileKey(fileKey []byte) error {
	// 2.A.f
	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	perm := make([]byte, 32)
	mode.CryptBlocks(perm, pa.info.Perms)
	if perm[9] != 'a' || perm[10] != 'd' || perm[11] != 'b' {
		return ErrInvalidPassword
	}
	return nil
}

// authenticateOwnerR6 implements owner password authentication for R6
func (pa *PasswordAuth) authenticateOwnerR6(password string) ([]byte, error) {
	// 2.A.a
	pw := []byte(password)
	// 2.A.b
	if len(pw) > 127 {
		pw = pw[:127]
	}

	// 2.A.c, 2.A.e is irrelevant in this func

	// 2.A.d
	h := sha256.New()
	h.Write(pw)
	h.Write(pa.info.O[40 : 40+8]) // key salt
	h.Write(pa.info.U)
	k0 := h.Sum(nil)
	k, err := pa.computeHashR6(password, k0, true)
	if err != nil {
		return nil, err
	}

	// 2.A.e
	block, _ := aes.NewCipher(k[:32])

	mode := cipher.NewCBCDecrypter(block, iv)
	fileKey := make([]byte, 32)
	mode.CryptBlocks(fileKey, pa.info.OE)

	if err := pa.validateFileKey(fileKey); err != nil {
		return nil, err
	}

	return fileKey, nil
}

// ValidatePermissions validates the permissions field for V5 encryption
func (pa *PasswordAuth) ValidatePermissions(key []byte) error {
	if pa.info.Revision < Revision5 {
		return nil
	}

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return err
	}

	if len(pa.info.Perms)%aes.BlockSize != 0 {
		return fmt.Errorf("invalid Perms length: not full AES blocks")
	}
	perms := make([]byte, len(pa.info.Perms))
	mode := newECBDecrypter(block)
	mode.CryptBlocks(perms, pa.info.Perms)

	// Check padding (last 8 bytes should be 'sAlT' + 4 bytes of padding)
	if len(perms) < 16 || !bytes.HasSuffix(perms, []byte("sAlT")) {
		return fmt.Errorf("invalid permissions padding")
	}

	// Extract permissions (first 4 bytes, big-endian)
	decryptedP := binary.BigEndian.Uint32(perms[:4])
	if decryptedP != pa.info.P {
		return fmt.Errorf("permissions validation failed")
	}

	return nil
}

// ecbDecrypter implements ECB decryption for AES
type ecbDecrypter struct {
	b cipher.Block
}

func newECBDecrypter(b cipher.Block) *ecbDecrypter {
	return &ecbDecrypter{b: b}
}

func (e *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(dst) < len(src) {
		panic("dst too short")
	}
	if len(src)%e.b.BlockSize() != 0 {
		panic("input not full blocks")
	}

	for len(src) > 0 {
		e.b.Decrypt(dst[:e.b.BlockSize()], src[:e.b.BlockSize()])
		dst = dst[e.b.BlockSize():]
		src = src[e.b.BlockSize():]
	}
}
