package main

import (
	"encoding/json"
	"net/http"
	"log"
	"os"
	"flag"
	//"errors"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"path/filepath"
	"github.com/julienschmidt/httprouter"
)

type config struct {
	HTTP string
}

// Tasks are encrypted with a symmetric key (EncryptedKey), which is
// encrypted with the asymmetric key in KeyFingerprint
type EncryptedTask struct {
	KeyFingerprint  string
	EncryptedKey    []byte
	Encrypted       []byte
	IV              []byte
}

type Task struct {
	User     string
	SampleID string
	//TODO
}

func aesDecrypt(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte(""), err
	}
	log.Printf("Blocksize: %d\n", block.BlockSize())
	//TODO: Think about it! is this secure?
	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)
	return ciphertext, nil
}

func rsaDecrypt(text []byte, key []byte) ([]byte, error) {
	//TODO
	return text, nil
}

func decryptTask(enc *EncryptedTask) (string, error) {
	//TODO: Fetch private key corresponding to enc.keyFingerprint (from where?)
	asymKey := []byte(enc.KeyFingerprint)
	
	//TODO: Actually implement decryption-function!
	//      For now: dec(a) = a
	// Decrypt symmetric key using the asymmetric key
	symKey, err := rsaDecrypt(enc.EncryptedKey, asymKey)
	if err != nil{
		return "", err
	}

	//TODO: Actually implement decryption-function!
	//      For now: dec(a) = a
	// Decrypt using the symmetric key
	decrypted, err := aesDecrypt(enc.Encrypted, symKey, enc.IV)
	return string(decrypted), err
}

func validateTask(task string) ([]Task, error) {
	var tasks []Task
	err := json.Unmarshal([]byte(task), &tasks)
	if err != nil {
		return nil, err
	}
	//TODO Check for required fields; Additional checks?
	return tasks, err
}

func checkACL(task Task) (error){
	//TODO: How shall ACL-Check be executed?
	return nil
}

func decodeTask(r *http.Request) (*EncryptedTask, error) {
	ek, err := base64.StdEncoding.DecodeString(r.FormValue("EncryptedKey"))
	if err != nil {
		return nil, err
	}
	iv, err := base64.StdEncoding.DecodeString(r.FormValue("iv"))
	if err != nil {
		return nil, err
	}
	en, err := base64.StdEncoding.DecodeString(r.FormValue("Encrypted"))
	if err != nil {
		return nil, err
	}

	task := EncryptedTask{
		KeyFingerprint : r.FormValue("KeyFingerprint"),
		EncryptedKey   : ek,
		Encrypted      : en,
		IV             : iv	}
	log.Printf("New task request:\n%+v\n", task);
	return &task, err
}

func httpRequestIncoming(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	task, err := decodeTask(r)
	if err != nil {
		log.Println("Error while decoding: ", err)
		return
	}
	decTask, err := decryptTask(task)
	if err != nil {
		log.Println("Error while decrypting: ", err)
		return
	}
	log.Println("Decrypted task:", decTask)
	tasks, err := validateTask(decTask)
	if err != nil {
		log.Println("Error while validating: ", err)
		return
	}
	for i := 0; i < len(tasks); i++ {
		err = checkACL(tasks[i])
		if err != nil {
			log.Println("Error while checking ACL: ", err)
			return
		}
	}
	log.Printf("%+v", tasks)

	// TODO: push to transport
}

func initHTTP(httpBinding string) {
	router := httprouter.New()
	router.GET("/task/*name", httpRequestIncoming)
	log.Printf("Listening on %s\n", httpBinding)
	log.Fatal(http.ListenAndServe(httpBinding, router))
}

func main() {
	var confPath string
	flag.StringVar(&confPath, "config", "", "Path to the config file")
	flag.Parse()

	if confPath == "" {
		confPath, _ = filepath.Abs(filepath.Dir(os.Args[0]))
		confPath += "/config.json"
	}

	conf := &config{}
	cfile, _ := os.Open(confPath)
	if err := json.NewDecoder(cfile).Decode(&conf); err != nil {
		log.Fatal("Couldn't read config file! ", err)
	}

	initHTTP(conf.HTTP)
}