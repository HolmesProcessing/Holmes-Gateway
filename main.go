package main

import (
	//"strings"
	"io/ioutil"
	"encoding/json"
	"net/http"
	"log"
	"os"
	"flag"
	"sync"
	//"errors"
	"crypto/sha256"
	"crypto/rsa"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"crypto/rand"
	"encoding/pem"
	"encoding/base64"
	"path/filepath"
	"github.com/julienschmidt/httprouter"
	"github.com/howeyc/fsnotify"
)

type config struct {
	HTTP    string
	KeyPath string
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

var keys map[string]rsa.PrivateKey
var keysMutex = &sync.Mutex{}

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

func rsaEncrypt(plaintext []byte, key *rsa.PrivateKey) ([]byte, error) {
	label := []byte("")
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, plaintext, label)
	return ciphertext, err
}

func rsaDecrypt(ciphertext []byte, key *rsa.PrivateKey) ([]byte, error) {
	label := []byte("")
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ciphertext, label)
	return plaintext, err
}

func decryptTask(enc *EncryptedTask) (string, error) {
	// Fetch private key corresponding to enc.keyFingerprint
	keysMutex.Lock()
	asymKey := keys[enc.KeyFingerprint]
	keysMutex.Unlock()
	
	// Decrypt symmetric key using the asymmetric key
	symKey, err := rsaDecrypt(enc.EncryptedKey, &asymKey)
	if err != nil{
		return "", err
	}

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

func loadKey(path string)(rsa.PrivateKey, string){
	log.Println(path)
	f, err := ioutil.ReadFile(path)
	if err != nil{
		log.Fatal("Error reading key (Read) ", err)
	}
	priv, rem := pem.Decode(f)
	if len(rem) != 0 {
		log.Fatal("Error reading key (Decode) ", rem)
	}
	key, err := x509.ParsePKCS1PrivateKey(priv.Bytes)
	if err != nil {
		log.Fatal("Error reading key (Parse) ", err)
	}

	// strip the path from its directory and ".priv"-extension
	path = filepath.Base(path)
	path = path[:len(path)-5]
	return rsa.PrivateKey(*key), path
}

func keyWalkFn(path string, fi os.FileInfo, err error) (error) {
	if fi.IsDir(){
		return nil
	}
	if !(filepath.Ext(path) == ".priv"){
		return nil
	}
	log.Println(path)
	key, name := loadKey(path)
	keysMutex.Lock()
	keys[name] = key
	keysMutex.Unlock()
	return nil
}

func readKeys(path string) {
	err := filepath.Walk(path, keyWalkFn)
	if err != nil {
		log.Fatal("Error loading keys ", err)
	}

	// Setup directory watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	// Process events
	go func() {
		for {
			select {
			case ev := <-watcher.Event:		
				if filepath.Ext(ev.Name) == ".priv" {
					log.Println("event:", ev)
					if ev.IsCreate(){
						log.Println("New private key", ev.Name)
						key, name := loadKey(ev.Name)
						keysMutex.Lock()
						keys[name] = key
						keysMutex.Unlock()
					} else if ev.IsDelete() || ev.IsRename(){
						// For renamed keys, there is a CREATE-event afterwards so it is just removed here
						log.Println("Removed private key", ev.Name)
						name := filepath.Base(ev.Name)
						name = name[:len(name)-5]
						keysMutex.Lock()
						delete(keys, name)
						keysMutex.Unlock()
					} else if ev.IsModify(){
						log.Println("Modified private key", ev.Name)
						name := filepath.Base(ev.Name)
						name = name[:len(name)-5]
						keysMutex.Lock()
						delete(keys, name)
						keysMutex.Unlock()

						key, name := loadKey(ev.Name)
						keysMutex.Lock()
						keys[name] = key
						keysMutex.Unlock()
					}
					//TODO remove printing of private keys
					log.Println(keys)

				}
			case err := <-watcher.Error:
				log.Println("error:", err)
			}
		}
	}()

	err = watcher.Watch(path)
	if err != nil {
		log.Fatal(err)
	}
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

	keys = make(map[string]rsa.PrivateKey)
	readKeys(conf.KeyPath)
	//TODO remove printing of private keys, as it creates a security risk!!!
	log.Println(keys)

	initHTTP(conf.HTTP)
}