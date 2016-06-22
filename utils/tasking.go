package tasking

import (
	"log"
	"bytes"
	"errors"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/rand"
)

// Tasks are encrypted with a symmetric key (EncryptedKey), which is
// encrypted with the asymmetric key in KeyFingerprint
type EncryptedTask struct {
	KeyFingerprint  string
	EncryptedKey    []byte
	Encrypted       []byte
	IV              []byte
}

type Task struct {
	PrimaryURI     string              `json:"primaryURI"`
	SecondaryURI   string              `json:"secondaryURI"`
	Filename       string              `json:"filename"`
	Tasks          map[string][]string `json:"tasks"`
	Tags           []string            `json:"tags"`
	Attempts       int                 `json:"attempts"`
}

func FailOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func AesEncrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte(""), err
	}
	mode := cipher.NewCBCEncrypter(block, iv)

	padLength := mode.BlockSize()-len(plaintext)%mode.BlockSize()
	ciphertext := make([]byte,len(plaintext))
	copy(ciphertext, plaintext)
	ciphertext = append(ciphertext, bytes.Repeat([]byte{byte(padLength)}, padLength)...)

	mode.CryptBlocks(ciphertext,ciphertext)
	return ciphertext, nil
}

func AesDecrypt(ciphertext []byte, key []byte, iv []byte) ( []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte(""), err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte,len(ciphertext))
	mode.CryptBlocks(plaintext,ciphertext)
	if len(plaintext) == 0 {
		return []byte(""), errors.New("Empty plaintext")
	}
	padLength := int(plaintext[len(plaintext)-1])
	if padLength > len(plaintext) {
		return []byte(""), errors.New("Invalid padding size")
	}
	plaintext = plaintext[:len(plaintext)-padLength]
	return plaintext, nil
}

func RsaEncrypt(plaintext []byte, key *rsa.PublicKey) ([]byte, error) {
	label := []byte("")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, plaintext, label)
	return ciphertext, err
}

func RsaDecrypt(ciphertext []byte, key *rsa.PrivateKey) ([]byte, error) {
	label := []byte("")
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ciphertext, label)
	return plaintext, err
}