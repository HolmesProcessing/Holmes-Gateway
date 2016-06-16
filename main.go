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
	"bytes"
	"errors"
	"crypto/sha256"
	"crypto/rsa"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"crypto/rand"
	"encoding/pem"
	"encoding/base64"
	"path/filepath"
	"github.com/howeyc/fsnotify"
	"github.com/streadway/amqp"
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

var conf *config
var keys map[string]rsa.PrivateKey
var keysMutex = &sync.Mutex{}
var rabbitChannel *amqp.Channel
var rabbitQueue amqp.Queue

func aesEncrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return []byte(""), err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	//ciphertext := make([]byte,len(plaintext)+mode.BlockSize-(len(plaintext)%mode.BlockSize))
	padLength := mode.BlockSize()-len(plaintext)%mode.BlockSize()
	ciphertext := make([]byte,len(plaintext))
	copy(ciphertext, plaintext)
	ciphertext = append(ciphertext, bytes.Repeat([]byte{byte(padLength)}, padLength)...)
	
	mode.CryptBlocks(ciphertext,ciphertext)
	return ciphertext, nil
}

func aesDecrypt(ciphertext []byte, key []byte, iv []byte) ( []byte, error) {
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
	log.Printf("Symmetric Key: %s\n", symKey)

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
	iv, err := base64.StdEncoding.DecodeString(r.FormValue("IV"))
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

func httpRequestIncoming(w http.ResponseWriter, r *http.Request) {
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
			continue
		}
		// Push to transport
		log.Printf("%+v\n", tasks[i])
		msgBody, err := json.Marshal(tasks[i])
		if err != nil {
			log.Println("Error while Marshalling: ", err)
		}
		log.Printf("marshalled: %s\n", msgBody)
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
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

func loadKey(path string)(rsa.PrivateKey, string){
	log.Println(path)
	f, err := ioutil.ReadFile(path)
	failOnError(err, "Error reading key (Read)")
	priv, rem := pem.Decode(f)
	if len(rem) != 0 {
		log.Fatal("Error reading key (Decode) ", rem)
	}
	key, err := x509.ParsePKCS1PrivateKey(priv.Bytes)
	failOnError(err, "Error reading key (Parse)")

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

func readKeys() {
	err := filepath.Walk(conf.KeyPath, keyWalkFn)
	failOnError(err, "Error loading keys ")

	// Setup directory watcher
	watcher, err := fsnotify.NewWatcher()
	failOnError(err, "Error setting up directory-watcher")

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
					//log.Println(keys)

				}
			case err := <-watcher.Error:
				log.Println("error:", err)
			}
		}
	}()

	err = watcher.Watch(conf.KeyPath)

	failOnError(err, "Error setting up directory-watcher")
}

func connectRabbit() {
	conn, err := amqp.Dial("amqp://"+conf.RabbitUser+":"+conf.RabbitPassword+"@"+conf.RabbitURI)
	failOnError(err, "Failed to connect to RabbitMQ")
	//defer conn.Close()

	rabbitChannel, err = conn.Channel()
	failOnError(err, "Failed to open a channel")
	//defer rabbitChannel.Close()

	rabbitQueue, err = rabbitChannel.QueueDeclare(
		conf.RabbitQueue, //name
		true,             // durable
		false,            // delete when unused
		false,            // exclusive
		false,            // no-wait
		nil,              // arguments
	)
	failOnError(err, "Failed to declare a queue")

	err = rabbitChannel.ExchangeDeclare(
		conf.Exchange,   // name
		"topic",         // type
		true,            // durable
		false,           // auto-deleted
		false,           // internal
		false,           // no-wait
		nil,             // arguments
	)
	failOnError(err, "Failed to declare an exchange")

	err = rabbitChannel.QueueBind(
		rabbitQueue.Name, // queue name
		conf.RoutingKey,  // routing key
		conf.Exchange,    // exchange
		false,            // nowait
		nil,              // arguments
	)
	failOnError(err, "Failed to bind queue")

	log.Printf("Connected to Rabbit on channel %s\n", rabbitQueue.Name)
}

func initHTTP() {
	http.HandleFunc("/task/", httpRequestIncoming)
	log.Printf("Listening on %s\n", conf.HTTP)
	log.Fatal(http.ListenAndServe(conf.HTTP, nil))
}

func main() {

	// Parse the configuration
	var confPath string
	flag.StringVar(&confPath, "config", "", "Path to the config file")
	flag.Parse()

	if confPath == "" {
		confPath, _ = filepath.Abs(filepath.Dir(os.Args[0]))
		confPath += "/config.json"
	}

	conf = &config{}
	cfile, _ := os.Open(confPath)
	err := json.NewDecoder(cfile).Decode(&conf)
	failOnError(err, "Couldn't read config file")
	
	// Parse the private keys
	keys = make(map[string]rsa.PrivateKey)
	readKeys()
	//log.Println(keys)

	// Connect to rabbitmq
	connectRabbit()

	// Setup the HTTP-listener
	initHTTP()
}