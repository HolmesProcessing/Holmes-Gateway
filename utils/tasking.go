package tasking

import (
	"log"
	"bytes"
	"time"
	"errors"
	"io/ioutil"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"encoding/json"
	"path/filepath"
)

type Ticket struct {
	Expiration  time.Time
	Tasks       []Task
	SignerKeyId string
	Signature   []byte
}

// Tasks are encrypted with a symmetric key (EncryptedKey), which is
// encrypted with the asymmetric key in KeyFingerprint
type Encrypted struct {
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

func Sign(message []byte, key *rsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(message)
	return rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
}

func Verify(signature []byte, message []byte, key *rsa.PublicKey) (error) {
	hashed := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], signature)
}

func VerifyTicket(ticket Ticket, key *rsa.PublicKey) (error) {
	sign := ticket.Signature
	ticket.Signature = nil
	log.Println("Verifying signature ", sign)
	msg, err := json.Marshal(ticket)
	if err != nil {
		return err
	}
	return Verify(sign, msg, key)
}

func AesDecrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
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

func LoadPrivateKey(path string)(*rsa.PrivateKey, string){
	log.Println(path)
	f, err := ioutil.ReadFile(path)
	FailOnError(err, "Error reading key (Read)")
	priv, rem := pem.Decode(f)
	if len(rem) != 0  || priv == nil{
		FailOnError(errors.New("Key not in pem-format"), "Error reading key (Decode)")
	}
	key, err := x509.ParsePKCS1PrivateKey(priv.Bytes)
	FailOnError(err, "Error reading key (Parse)")

	// strip the path from its directory and ".priv"-extension
	path = filepath.Base(path)
	path = path[:len(path)-5]
	return (*rsa.PrivateKey)(key), path
}

func LoadPublicKey(path string)(*rsa.PublicKey, string){
	log.Println(path)
	f, err := ioutil.ReadFile(path)
	FailOnError(err, "Error reading key (Read)")
	pub, rem := pem.Decode(f)
	if len(rem) != 0  || pub == nil{
		FailOnError(errors.New("Key not in pem-format"), "Error reading key (Decode)")
	}
	key, err := x509.ParsePKIXPublicKey(pub.Bytes)
	FailOnError(err, "Error reading key (Parse)")

	// strip the path from its directory and ".pub"-extension
	path = filepath.Base(path)
	path = path[:len(path)-4]
	return key.(*rsa.PublicKey), path
}
