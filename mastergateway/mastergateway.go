package mastergateway

import (
	"os"
	"log"
	"sync"
	"io/ioutil"
	"errors"
	"net/http"
	"crypto/rsa"
	"crypto/x509"
	"path/filepath"
	"encoding/pem"
	"encoding/json"
	"encoding/base64"
	"github.com/howeyc/fsnotify"
	"github.com/HolmesProcessing/Holmes-Gateway/utils"
)

type config struct {
	HTTP           string
	KeyPath        string
}

var (
	conf *config
	keys map[string]*rsa.PublicKey
	keysMutex = &sync.Mutex{}
)

func encryptKey(symKey []byte, asymKeyId string) ([]byte, error) {
	// Fetch public key
	keysMutex.Lock()
	asymKey, exists := keys[asymKeyId]
	keysMutex.Unlock()
	log.Println("searching for key: " + asymKeyId)
	log.Printf("%+v\n", keys)
	if !exists {
		return nil, errors.New("Public Key not found")
	}
	encrypted, err := tasking.RsaEncrypt(symKey, asymKey)
	return encrypted, err
}

func encryptTask(task string, asymKeyId string, symKey []byte, iv []byte) (*tasking.EncryptedTask, error) {

	encKey, err := encryptKey(symKey, asymKeyId)
	if err != nil {
		return nil, err
	}

	// Decrypt using the symmetric key
	encrypted, err := tasking.AesEncrypt([]byte(task), symKey, iv)
	if err != nil {
		return nil, err
	}
	encryptedTask := tasking.EncryptedTask {
		KeyFingerprint : asymKeyId,
		EncryptedKey : encKey,
		Encrypted : encrypted,
		IV : iv	}
	return &encryptedTask, err
}

func requestTask(uri string, encryptedTask *tasking.EncryptedTask) (error) {
	req, err := http.NewRequest("GET", uri, nil)
	q := req.URL.Query()
	q.Add("KeyFingerprint", encryptedTask.KeyFingerprint)
	q.Add("EncryptedKey", base64.StdEncoding.EncodeToString(encryptedTask.EncryptedKey))
	q.Add("IV", base64.StdEncoding.EncodeToString(encryptedTask.IV))
	q.Add("Encrypted", base64.StdEncoding.EncodeToString(encryptedTask.Encrypted))
	req.URL.RawQuery = q.Encode()
	log.Println(req.URL)
	client := &http.Client{}
	resp, err := client.Do(req)

	log.Println(resp)
	return err
}

func handleTask(task string) (error) {
	// TODO: Find out, which source the task belongs to
	// TODO: Check known organizations and chose one
	uri := "http://localhost:8080/task/"
	// TODO: Retrieve the corresponding public key
	asymKeyId := "blub"

	// TODO: Choose AES-key and IV
	symKey := []byte("abcdef0123456789")
	iv := []byte("0000111122223333")

	// Encrypt the task and the AES-key
	et, err := encryptTask(task, asymKeyId, symKey, iv)
	if err != nil {
		log.Println("Error while encrypting: ", err)
		return err
	}
	// TODO: Issue HTTP-GET-Request
	err = requestTask(uri, et)
	if err != nil {
		log.Println("Error requesting task: ", err)
		return err
	}
	return err
}

func loadPublicKey(path string)(*rsa.PublicKey, string){
	log.Println(path)
	f, err := ioutil.ReadFile(path)
	tasking.FailOnError(err, "Error reading key (Read)")
	pub, rem := pem.Decode(f)
	if len(rem) != 0  || pub == nil{
		tasking.FailOnError(errors.New("Key not in pem-format"), "Error reading key (Decode)")
	}
	key, err := x509.ParsePKIXPublicKey(pub.Bytes)
	tasking.FailOnError(err, "Error reading key (Parse)")

	// strip the path from its directory and ".pub"-extension
	path = filepath.Base(path)
	path = path[:len(path)-4]
	return key.(*rsa.PublicKey), path
}

func keyWalkFn(path string, fi os.FileInfo, err error) (error) {
	if fi.IsDir(){
		return nil
	}
	if !(filepath.Ext(path) == ".pub"){
		return nil
	}
	key, name := loadPublicKey(path)
	keysMutex.Lock()
	keys[name] = key
	keysMutex.Unlock()
	return nil
}

func dirWatcher(watcher *fsnotify.Watcher) {
	for {
		select {
		case ev := <-watcher.Event:		
			if filepath.Ext(ev.Name) != ".pub" {
				continue
			}
			log.Println("event:", ev)
			if ev.IsCreate(){
				log.Println("New public key", ev.Name)
				key, name := loadPublicKey(ev.Name)
				keysMutex.Lock()
				keys[name] = key
				keysMutex.Unlock()
			} else if ev.IsDelete() || ev.IsRename(){
				// For renamed keys, there is a CREATE-event afterwards so it is just removed here
				log.Println("Removed public key", ev.Name)
				name := filepath.Base(ev.Name)
				name = name[:len(name)-5]
				keysMutex.Lock()
				delete(keys, name)
				keysMutex.Unlock()
			} else if ev.IsModify(){
				log.Println("Modified public key", ev.Name)
				name := filepath.Base(ev.Name)
				name = name[:len(name)-5]
				keysMutex.Lock()
				delete(keys, name)
				keysMutex.Unlock()

				key, name := loadPublicKey(ev.Name)
				keysMutex.Lock()
				keys[name] = key
				keysMutex.Unlock()
			}
			//log.Println(keys)

		case err := <-watcher.Error:
			log.Println("error:", err)
		}
	}
}

func readKeys() {
	err := filepath.Walk(conf.KeyPath, keyWalkFn)
	tasking.FailOnError(err, "Error loading keys ")

	// Setup directory watcher
	watcher, err := fsnotify.NewWatcher()
	tasking.FailOnError(err, "Error setting up directory-watcher")

	// Process events
	go dirWatcher(watcher)

	err = watcher.Watch(conf.KeyPath)

	tasking.FailOnError(err, "Error setting up directory-watcher")
}

func httpRequestIncoming(w http.ResponseWriter, r *http.Request) {
	task := r.FormValue("task")
	err := handleTask(task)
	if err != nil {
		log.Println(err)
	}
}

func initHTTP() {
	http.HandleFunc("/task/", httpRequestIncoming)
	log.Printf("Listening on %s\n", conf.HTTP)
	log.Fatal(http.ListenAndServe(conf.HTTP, nil))
}

func Start(confPath string) {
	// Parse the configuration
	conf = &config{}
	cfile, _ := os.Open(confPath)
	err := json.NewDecoder(cfile).Decode(&conf)
	tasking.FailOnError(err, "Couldn't read config file")
	
	// Parse the public keys
	keys = make(map[string]*rsa.PublicKey)
	readKeys()
	//log.Println(keys)

	// Setup the HTTP-listener
	initHTTP()
}