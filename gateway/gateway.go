package gateway

import (
	"log"
	"os"
	"sync"
	"errors"
	"io/ioutil"
	"net/http"
	"crypto/x509"
	"crypto/rsa"
	"encoding/pem"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"github.com/howeyc/fsnotify"
	"github.com/streadway/amqp"
	"github.com/HolmesProcessing/Holmes-Gateway/utils"
)

type config struct {
	HTTP           string
	KeyPath        string
	RabbitURI      string
	RabbitUser     string
	RabbitPassword string
	RabbitQueue    string
	RoutingKey     string
	Exchange       string
}


var conf *config
var keys map[string]*rsa.PrivateKey
var keysMutex = &sync.Mutex{}
var rabbitChannel *amqp.Channel
var rabbitQueue amqp.Queue

func decryptTask(enc *tasking.EncryptedTask) (string, error) {
	// Fetch private key corresponding to enc.keyFingerprint
	keysMutex.Lock()
	asymKey, exists := keys[enc.KeyFingerprint]
	keysMutex.Unlock()
	if !exists {
		return "", errors.New("Private key not found")
	}
	
	// Decrypt symmetric key using the asymmetric key
	symKey, err := tasking.RsaDecrypt(enc.EncryptedKey, asymKey)
	if err != nil{
		return "", err
	}
	log.Printf("Symmetric Key: %s\n", symKey)

	// Decrypt using the symmetric key
	decrypted, err := tasking.AesDecrypt(enc.Encrypted, symKey, enc.IV)
	return string(decrypted), err
}

func stringPrintable(s string) (bool) {
	for i := 0; i < len(s); i++{
		c := int(s[i])
		if c < 0x9 || (c > 0x0d && c < 0x20) || (c >0x7e){
			return false
		}
	}
	return true
}

func validateTask(task string) ([]tasking.Task, error) {
	var tasks []tasking.Task
	err := json.Unmarshal([]byte(task), &tasks)
	if err != nil {
		return nil, err
	}
	// Check for required fields; Check whether strings are in printable ascii-range
	for i := 0; i < len(tasks); i++ {
		t := tasks[i]
		log.Printf("Validating %+v\n", t)
		if t.PrimaryURI == "" || !stringPrintable(t.PrimaryURI) {
			return nil, errors.New("Invalid Task (PrimaryURI invalid)")
		}
		if !stringPrintable(t.SecondaryURI) {
			return nil, errors.New("Invalid Task (SecondaryURI invalid)")
		}
		if t.Filename == "" || !stringPrintable(t.Filename) {
			return nil, errors.New("Invalid Task (Filename invalid)")
		}
		if len(t.Tasks) == 0 {
			return nil, errors.New("Invalid Task")
		}
		for k := range t.Tasks {
			if k == "" || !stringPrintable(k) {
				return nil, errors.New("Invalid Task")
			}
		}
		for j := 0; j < len(t.Tags); j++ {
			if !stringPrintable(t.Tags[j]) {
				return nil, errors.New("Invalid Task (Tag invalid)")
			}
		}
		if t.Attempts < 0 {
			return nil, errors.New("Invalid Task (Negative number of attempts)")
		}
	}

	return tasks, err
}

func checkACL(task tasking.Task) (error){
	//TODO: How shall ACL-Check be executed?
	return nil
}

func decodeTask(r *http.Request) (*tasking.EncryptedTask, error) {
	ek, err := base64.StdEncoding.DecodeString(r.FormValue("EncryptedKey"))
	if err != nil {
		return nil, err
	}
	iv, err := base64.StdEncoding.DecodeString(r.FormValue("IV"))
	if err != nil {
		return nil, err
	}
	en, err := base64.StdEncoding.DecodeString(r.FormValue("Encrypted"))
	if err != nil {
		return nil, err
	}

	task := tasking.EncryptedTask{
		KeyFingerprint : r.FormValue("KeyFingerprint"),
		EncryptedKey   : ek,
		Encrypted      : en,
		IV             : iv	}
	log.Printf("New task request:\n%+v\n", task);
	return &task, err
}

func handleTask(task *tasking.EncryptedTask) (error){
	decTask, err := decryptTask(task)
	if err != nil {
		log.Println("Error while decrypting: ", err)
		return err
	}
	log.Println("Decrypted task:", decTask)
	tasks, err := validateTask(decTask)
	if err != nil {
		log.Println("Error while validating: ", err)
		return err
	}
	for i := 0; i < len(tasks); i++ {
		err = checkACL(tasks[i])
		if err != nil {
			log.Println("Error while checking ACL: ", err)
			continue
		}
		// Push to transport
		log.Printf("%+v\n", tasks[i])
		msgBody, err := json.Marshal(tasks[i])
		if err != nil {
			log.Println("Error while Marshalling: ", err)
			continue
		}
		log.Printf("Marshalled: %s\n", msgBody)
		err = rabbitChannel.Publish(
			conf.Exchange,    // exchange
			conf.RoutingKey,  // key
			false,            // mandatory
			false,            // immediate
			amqp.Publishing {DeliveryMode: amqp.Persistent, ContentType: "text/plain", Body: []byte(msgBody),}) //msg
		if err != nil {
			log.Println("Error while pushing to transport: ", err)
			continue
		}
	}
	// TODO: Actually collect all the errors for individual tasks and return them
	return nil
}

func httpRequestIncoming(w http.ResponseWriter, r *http.Request) {
	task, err := decodeTask(r)
	if err != nil {
		log.Println("Error while decoding: ", err)
		return
	}

	handleTask(task)
	// TODO: Send an answer (fail/success)
}

func loadPrivateKey(path string)(*rsa.PrivateKey, string){
	log.Println(path)
	f, err := ioutil.ReadFile(path)
	tasking.FailOnError(err, "Error reading key (Read)")
	priv, rem := pem.Decode(f)
	if len(rem) != 0  || priv == nil{
		tasking.FailOnError(errors.New("Key not in pem-format"), "Error reading key (Decode)")
	}
	key, err := x509.ParsePKCS1PrivateKey(priv.Bytes)
	tasking.FailOnError(err, "Error reading key (Parse)")

	// strip the path from its directory and ".priv"-extension
	path = filepath.Base(path)
	path = path[:len(path)-5]
	return (*rsa.PrivateKey)(key), path
}

func keyWalkFn(path string, fi os.FileInfo, err error) (error) {
	if fi.IsDir(){
		return nil
	}
	if !(filepath.Ext(path) == ".priv"){
		return nil
	}
	key, name := loadPrivateKey(path)
	keysMutex.Lock()
	keys[name] = key
	keysMutex.Unlock()
	return nil
}

func dirWatcher(watcher *fsnotify.Watcher) {
	for {
		select {
		case ev := <-watcher.Event:		
			if filepath.Ext(ev.Name) != ".priv" {
				continue
			}
			log.Println("event:", ev)
			if ev.IsCreate(){
				log.Println("New private key", ev.Name)
				key, name := loadPrivateKey(ev.Name)
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

				key, name := loadPrivateKey(ev.Name)
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

func connectRabbit() {
	conn, err := amqp.Dial("amqp://"+conf.RabbitUser+":"+conf.RabbitPassword+"@"+conf.RabbitURI)
	tasking.FailOnError(err, "Failed to connect to RabbitMQ")
	//defer conn.Close()

	rabbitChannel, err = conn.Channel()
	tasking.FailOnError(err, "Failed to open a channel")
	//defer rabbitChannel.Close()

	rabbitQueue, err = rabbitChannel.QueueDeclare(
		conf.RabbitQueue, //name
		true,             // durable
		false,            // delete when unused
		false,            // exclusive
		false,            // no-wait
		nil,              // arguments
	)
	tasking.FailOnError(err, "Failed to declare a queue")

	err = rabbitChannel.ExchangeDeclare(
		conf.Exchange,   // name
		"topic",         // type
		true,            // durable
		false,           // auto-deleted
		false,           // internal
		false,           // no-wait
		nil,             // arguments
	)
	tasking.FailOnError(err, "Failed to declare an exchange")

	err = rabbitChannel.QueueBind(
		rabbitQueue.Name, // queue name
		conf.RoutingKey,  // routing key
		conf.Exchange,    // exchange
		false,            // nowait
		nil,              // arguments
	)
	tasking.FailOnError(err, "Failed to bind queue")

	log.Printf("Connected to Rabbit on channel %s\n", rabbitQueue.Name)
}

func initHTTP() {
	http.HandleFunc("/task/", httpRequestIncoming)
	log.Printf("Listening on %s\n", conf.HTTP)
	log.Fatal(http.ListenAndServe(conf.HTTP, nil))
}

func Start(confPath string) {
	conf = &config{}
	cfile, _ := os.Open(confPath)
	err := json.NewDecoder(cfile).Decode(&conf)
	tasking.FailOnError(err, "Couldn't read config file")
	
	// Parse the private keys
	keys = make(map[string]*rsa.PrivateKey)
	readKeys()
	//log.Println(keys)

	// Connect to rabbitmq
	connectRabbit()

	// Setup the HTTP-listener
	initHTTP()
}