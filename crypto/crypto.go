/*
arqinator: arq/types/crypto.go
Implements cryptography for encrypted Arq files.

Copyright 2015 Asim Ihsan

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package crypto

// https://code.google.com/p/rsc/source/browse/arq/crypto.go

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	//log "github.com/sirupsen/logrus"
)

const (
	AES_KEY_LEN_BYTES = 32
	HMAC_LEN          = 32
	IV_LEN            = 16
)

type CryptoState struct {
	c        cipher.Block
	hmac     hash.Hash
	sha_salt []byte
}

func AesCBCDecrypt(src []byte, iv []byte, c cipher.Block) ([]byte, error) {
	decryptor := cipher.NewCBCDecrypter(c, iv)
	dst := make([]byte, len(src))
	decryptor.CryptBlocks(dst, src)
	pad := dst[len(dst)-1]
	if pad > 16 {
		return nil, errors.New("Incorrect padding")
	}
	for i := 1; i <= int(pad); i++ {
		if dst[len(dst)-i] != pad {
			return nil, errors.New("Incorrect padding")
		}
	}
	dst = dst[:len(dst)-int(pad)]

	return dst, nil
}
func NewCryptoState(password []byte, encDatFile []byte) (*CryptoState, error) {
	const (
		PBKDF2_ITERATIONS = 200000
		HEADER_LEN        = 12
		SALT_LEN          = 8
		MASTER_KEY_SIZE   = 32
	)
	offset := 0
	header := encDatFile[offset : offset+HEADER_LEN]
	offset += HEADER_LEN

	salt := encDatFile[offset : offset+SALT_LEN]
	offset += SALT_LEN

	key_hmac := encDatFile[offset : offset+HMAC_LEN]
	offset += HMAC_LEN

	iv := encDatFile[offset : offset+IV_LEN]
	offset += IV_LEN

	enc_master_keys := encDatFile[offset:]

	if string(header) != "ENCRYPTIONV2" {
		return nil, errors.New("Unexpected header in encryptionv3.dat")
	}

	user_key := pbkdf2.Key(password, salt, PBKDF2_ITERATIONS,
		AES_KEY_LEN_BYTES*2, sha1.New)

	// Validate the password
	h := hmac.New(sha256.New, user_key[32:])
	h.Write(iv)
	h.Write(enc_master_keys)
	if !bytes.Equal(key_hmac, h.Sum(nil)) {
		return nil, errors.New("Incorrect password")
	}

	c, err := aes.NewCipher(user_key[:32])
	if err != nil {
		return nil, err
	}

	master_keys, err := AesCBCDecrypt(enc_master_keys, iv, c)
	if err != nil {
		return nil, errors.New("Error decrypting master keys")
	}

	state := CryptoState{}

	if state.c, err = aes.NewCipher(master_keys[:MASTER_KEY_SIZE]); err != nil {
		return nil, err
	}
	state.hmac = hmac.New(sha256.New, master_keys[MASTER_KEY_SIZE:MASTER_KEY_SIZE*2])
	state.sha_salt = make([]byte, MASTER_KEY_SIZE)
	copy(state.sha_salt, master_keys[MASTER_KEY_SIZE*2:MASTER_KEY_SIZE*3])
	return &state, nil
}

func (s *CryptoState) Decrypt(data []byte) ([]byte, error) {
	data = bytes.TrimPrefix(data, []byte("encrypted"))
	data = bytes.TrimPrefix(data, []byte("ARQO"))
	hmac := data[:HMAC_LEN]
	data = data[HMAC_LEN:]

	master_iv := data[:IV_LEN]
	data = data[IV_LEN:]

	enc_data_iv_key := data[:IV_LEN*2+AES_KEY_LEN_BYTES]
	data = data[IV_LEN*2+AES_KEY_LEN_BYTES:]

	s.hmac.Reset()
	s.hmac.Write(master_iv)
	s.hmac.Write(enc_data_iv_key)
	s.hmac.Write(data)
	if !bytes.Equal(hmac, s.hmac.Sum(nil)) {
		return nil, errors.New("Failed hmac check in decrypt")
	}

	data_iv_key, err := AesCBCDecrypt(enc_data_iv_key, master_iv, s.c)
	if err != nil {
		return nil, err
	}
	data_iv := data_iv_key[:IV_LEN]
	data_key := data_iv_key[IV_LEN:]

	c, err := aes.NewCipher(data_key)
	if err != nil {
		return nil, err
	}

	return AesCBCDecrypt(data, data_iv, c)
}
