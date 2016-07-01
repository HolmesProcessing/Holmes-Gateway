package mastergateway

import (
	"os"
	"io"
	"log"
	"sync"
	"time"
	"errors"
	"net/http"
	"crypto/rsa"
	"crypto/rand"
	"path/filepath"
	"encoding/json"
	"encoding/base64"
	"github.com/howeyc/fsnotify"
	"../utils"
)

type config struct {
	HTTP                string // The HTTP-binding for listening (IP+Port)
	SourcesKeysPath     string // Path to the public keys of the sources
	TicketSignKeyPath   string // Path to the private key used for signing tickets
}

var (
	conf *config                   // The configuration struct
	keys map[string]*rsa.PublicKey // The public keys of the sources
	keysMutex = &sync.Mutex{}      // Mutex for the map, since keys could change during runtime
	ticketSignKey *rsa.PrivateKey  // The private key used for signing tickets
	ticketSignKeyName string       // The id of the private key used for signing tickets
)

func createTicket(tasks []tasking.Task) (tasking.Ticket, error){
	t := tasking.Ticket {
		Expiration : time.Now().Add(3*time.Hour), //TODO: 3 Hours validity reasonable?
		Tasks : tasks,
		SignerKeyId : ticketSignKeyName,
		Signature : nil }
	msg, err := json.Marshal(t)
	if err != nil {
		return t, err
	}
	t.Signature, err = tasking.Sign(msg, ticketSignKey)
	return t, err
}

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

func encryptTicket(ticket []byte, asymKeyId string, symKey []byte, iv []byte) (*tasking.Encrypted, error) {

	encKey, err := encryptKey(symKey, asymKeyId)
	if err != nil {
		return nil, err
	}

	// Decrypt using the symmetric key
	encrypted, err := tasking.AesEncrypt(ticket, symKey, iv)
	if err != nil {
		return nil, err
	}
	encryptedTicket := tasking.Encrypted {
		KeyFingerprint : asymKeyId,
		EncryptedKey : encKey,
		Encrypted : encrypted,
		IV : iv	}
	return &encryptedTicket, err
}

func requestTask(uri string, encryptedTicket *tasking.Encrypted) (error) {
	req, err := http.NewRequest("GET", uri, nil)
	q := req.URL.Query()
	q.Add("KeyFingerprint", encryptedTicket.KeyFingerprint)
	q.Add("EncryptedKey", base64.StdEncoding.EncodeToString(encryptedTicket.EncryptedKey))
	q.Add("IV", base64.StdEncoding.EncodeToString(encryptedTicket.IV))
	q.Add("Encrypted", base64.StdEncoding.EncodeToString(encryptedTicket.Encrypted))
	req.URL.RawQuery = q.Encode()
	log.Println(req.URL)
	client := &http.Client{}
	resp, err := client.Do(req)

	log.Println(resp)
	return err
}

func handleTask(tasksStr string) (error) {
	// TODO: Check ACL!
	// TODO: Find out, which source the task belongs to
	// TODO: Check known organizations and chose one
	uri := "http://localhost:8080/task/"
	// TODO: Retrieve the corresponding public key
	asymKeyId := "blub"

	// Choose AES-key and IV
	symKey := make([]byte, 16) //TODO: Length 16 OK?
	if _, err := io.ReadFull(rand.Reader, symKey); err != nil {
		log.Println("Error while creating AES-key: ", err)
		return err
	}
	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Println("Error while creating IV: ", err)
		return err
	}

	var tasks []tasking.Task
	err := json.Unmarshal([]byte(tasksStr), &tasks)
	if err != nil {
		log.Println("Error while Unmarshalling tasks: ", err)
		return err
	}
	ticket, err := createTicket(tasks)
	if err != nil {
		log.Println("Error while creating Ticket: ", err)
		return err
	}

	ticketM, err := json.Marshal(ticket)
	if err != nil {
		log.Println("Error while Marshalling ticket: ", err)
		return err
	}

	// Encrypt the ticket and the AES-key
	et, err := encryptTicket(ticketM, asymKeyId, symKey, iv)
	if err != nil {
		log.Println("Error while encrypting: ", err)
		return err
	}
	// Issue HTTP-GET-Request
	err = requestTask(uri, et)
	if err != nil {
		log.Println("Error requesting task: ", err)
		return err
	}
	return err
}

func keyWalkFn(path string, fi os.FileInfo, err error) (error) {
	if fi.IsDir(){
		return nil
	}
	if !(filepath.Ext(path) == ".pub"){
		return nil
	}
	key, name := tasking.LoadPublicKey(path)
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
				key, name := tasking.LoadPublicKey(ev.Name)
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

				key, name := tasking.LoadPublicKey(ev.Name)
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
	err := filepath.Walk(conf.SourcesKeysPath, keyWalkFn)
	tasking.FailOnError(err, "Error loading keys ")

	// Setup directory watcher
	watcher, err := fsnotify.NewWatcher()
	tasking.FailOnError(err, "Error setting up directory-watcher")

	// Process events
	go dirWatcher(watcher)

	err = watcher.Watch(conf.SourcesKeysPath)

	tasking.FailOnError(err, "Error setting up directory-watcher")

	ticketSignKey, ticketSignKeyName = tasking.LoadPrivateKey(conf.TicketSignKeyPath)
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
