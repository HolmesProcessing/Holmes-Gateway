package gateway

import (
	"log"
	"os"
	"sync"
	"time"
	"errors"
	"net/http"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/streadway/amqp"
	"../utils"
)

type config struct {
	HTTP             string
	SourcesKeysPath  string
	TicketKeysPath   string
	SampleStorageURI string
	RabbitURI        string
	RabbitUser       string
	RabbitPassword   string
	RabbitQueue      string
	RoutingKey       string
	Exchange         string
	RabbitQueueLong  string
	RoutingKeyLong   string
	ExchangeLong     string
}


var conf *config
var keys map[string]*rsa.PrivateKey
var ticketKeys map[string]*rsa.PublicKey
var keysMutex = &sync.Mutex{}
var rabbitChannel *amqp.Channel
var rabbitQueue amqp.Queue
var rabbitChannelLong *amqp.Channel
var rabbitQueueLong amqp.Queue

func decryptTicket(enc *tasking.Encrypted) (string, error, []byte) {
	// Fetch private key corresponding to enc.keyFingerprint
	keysMutex.Lock()
	asymKey, exists := keys[enc.KeyFingerprint]
	keysMutex.Unlock()
	if !exists {
		return "", errors.New("Private key " + enc.KeyFingerprint + " not found"), nil
	}
	
	// Decrypt symmetric key using the asymmetric key
	symKey, err := tasking.RsaDecrypt(enc.EncryptedKey, asymKey)
	if err != nil{
		return "", err, nil
	}
	//log.Printf("Symmetric Key: %s\n", symKey)

	// Decrypt using the symmetric key
	decrypted, err := tasking.AesDecrypt(enc.Encrypted, symKey, enc.IV)
	return string(decrypted), err, symKey
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

func checkTask(task *tasking.Task) (error){
	log.Printf("Validating %+v\n", task)
	if task.PrimaryURI == "" || !stringPrintable(task.PrimaryURI) {
		return errors.New("Invalid Task (PrimaryURI invalid)")
	}
	if !stringPrintable(task.SecondaryURI) {
		return errors.New("Invalid Task (SecondaryURI invalid)")
	}
	if task.Filename == "" || !stringPrintable(task.Filename) {
		return errors.New("Invalid Task (Filename invalid)")
	}
	if len(task.Tasks) == 0 {
		return errors.New("Invalid Task")
	}
	for k := range task.Tasks {
		if k == "" || !stringPrintable(k) {
			return errors.New("Invalid Task")
		}
	}
	for j := 0; j < len(task.Tags); j++ {
		if !stringPrintable(task.Tags[j]) {
			return errors.New("Invalid Task (Tag invalid)")
		}
	}
	if task.Attempts < 0 {
		return errors.New("Invalid Task (Negative number of attempts)")
	}
	return nil
}

func handleDecrypted(ticketStr string) (error, []tasking.TaskError) {
	tskerrors := make([]tasking.TaskError,0)
	var ticket tasking.Ticket
	err := json.Unmarshal([]byte(ticketStr), &ticket)
	if err != nil {
		return err, tskerrors
	}

	// Check ticket for validity
	signKey, found := ticketKeys[ticket.SignerKeyId]
	if !found {
		return errors.New("Couldn't verify signature: Key unknown"), tskerrors
	}
	err = tasking.VerifyTicket(ticket, signKey)
	if err != nil {
		log.Println("Ticket invalid!")
		return err, tskerrors
	}
	log.Println("Signature OK!")
	// Signature is OK

	if time.Now().After(ticket.Expiration) {
		return errors.New("Ticket expired"), tskerrors
	}
	//TODO: Check ACL

	// Check for required fields; Check whether strings are in printable ascii-range
	for i := 0; i < len(ticket.Tasks); i++ {
		task := ticket.Tasks[i]
		e := checkTask(&task)
		task.PrimaryURI = conf.SampleStorageURI + task.PrimaryURI
		if task.SecondaryURI != "" {
			task.SecondaryURI = conf.SampleStorageURI + task.SecondaryURI
		}
		if e != nil {
			e2 := tasking.MyError{Error: e}
			tskerrors = append(tskerrors, tasking.TaskError{
				TaskStruct : task,
				Error : e2})
		} else {
			pushToTransport(task)
		}
	}

	return err, tskerrors
}

func decodeTask(r *http.Request) (*tasking.Encrypted, error) {
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

	task := tasking.Encrypted{
		KeyFingerprint : r.FormValue("KeyFingerprint"),
		EncryptedKey   : ek,
		Encrypted      : en,
		IV             : iv	}
	log.Printf("New task request:\n%+v\n", task);
	return &task, err
}

func pushToTransport(task tasking.Task) {
	log.Printf("%+v\n", task)
	msgBody, err := json.Marshal(task)
	if err != nil {
		log.Println("Error while Marshalling: ", err)
		return
	}
	if task.Long {
		log.Printf("Pushing to long: \x1b[0;32m%s\x1b[0m\n", msgBody)
		err = rabbitChannelLong.Publish(
			conf.ExchangeLong,   // exchange
			conf.RoutingKeyLong, // key
			false,               // mandatory
			false,               // immediate
			amqp.Publishing {DeliveryMode: amqp.Persistent, ContentType: "text/plain", Body: msgBody,}) //msg

	} else {
		log.Printf("Pushing: \x1b[0;32m%s\x1b[0m\n", msgBody)
		err = rabbitChannel.Publish(
			conf.Exchange,    // exchange
			conf.RoutingKey,  // key
			false,            // mandatory
			false,            // immediate
			amqp.Publishing {DeliveryMode: amqp.Persistent, ContentType: "text/plain", Body: msgBody,}) //msg
	}
	if err != nil {
		log.Println("Error while pushing to transport: ", err)
		return
	}
}

func handleIncoming(task *tasking.Encrypted) (error, []tasking.TaskError, []byte){
	decTicket, err, symKey := decryptTicket(task)
	if err != nil {
		log.Println("Error while decrypting: ", err)
		return err, nil, symKey
	}
	log.Println("Decrypted ticket:", decTicket)
	err, tskerrors := handleDecrypted(decTicket)
	if err != nil {
		log.Println("Error: ", err)
		return err, nil, symKey
	}
	// return all the collected errors for individual tasks
	return nil, tskerrors, symKey
}

func httpRequestIncoming(w http.ResponseWriter, r *http.Request) {
	task, err := decodeTask(r)
	if err != nil {
		log.Println("Error while decoding: ", err)
		w.Write([]byte(err.Error()))
		return
	}

	err, tskerrors, symKey := handleIncoming(task)
	// encrypt answer
	task.IV[0] ^= 1 // Do not reuse the same IV -> modify one bit
	if err != nil {
		enc, _ := tasking.AesEncrypt([]byte(err.Error()), symKey, task.IV)
		w.Write(enc)
	} else {
		log.Printf("Collected errors: %+v", tskerrors)
		x, _ := json.Marshal(tskerrors)
		enc, _ := tasking.AesEncrypt(x, symKey, task.IV)
		w.Write(enc)
	}
}

func readKeys() {
	// Load the private keys for the sources
	tasking.LoadKeysAndWatch(conf.SourcesKeysPath, ".priv",
		func(name string){
			keysMutex.Lock()
			delete(keys, name)
			keysMutex.Unlock()
			log.Println(keys)
		},
		func(name string){
			key, name, err := tasking.LoadPrivateKey(name)
			if err != nil {
				log.Printf("Error reading key (%s):%s\n", name, err)
				return
			}

			keysMutex.Lock()
			keys[name] = key
			keysMutex.Unlock()
			log.Println(keys)
		})

	// Load the public keys for the tickets
	tasking.LoadKeysAndWatch(conf.TicketKeysPath, ".pub",
		func(name string){
			keysMutex.Lock()
			delete(ticketKeys, name)
			keysMutex.Unlock()
			log.Println(ticketKeys)
		},
		func(name string){
			key, name, err := tasking.LoadPublicKey(name)
			if err != nil {
				log.Printf("Error reading key (%s):%s\n", name, err)
				return
			}
			keysMutex.Lock()
			ticketKeys[name] = key
			keysMutex.Unlock()
			log.Println(ticketKeys)
	})
	
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

	// Long
	rabbitChannelLong, err = conn.Channel()
	tasking.FailOnError(err, "Failed to open a channel")
	rabbitQueue, err = rabbitChannelLong.QueueDeclare(
		conf.RabbitQueueLong, //name
		true,                 // durable
		false,                // delete when unused
		false,                // exclusive
		false,                // no-wait
		nil,                  // arguments
	)
	tasking.FailOnError(err, "Failed to declare a queue")

	err = rabbitChannelLong.ExchangeDeclare(
		conf.ExchangeLong, // name
		"topic",           // type
		true,              // durable
		false,             // auto-deleted
		false,             // internal
		false,             // no-wait
		nil,               // arguments
	)
	tasking.FailOnError(err, "Failed to declare an exchange")

	err = rabbitChannelLong.QueueBind(
		rabbitQueueLong.Name, // queue name
		conf.RoutingKeyLong,  // routing key
		conf.ExchangeLong,    // exchange
		false,                // nowait
		nil,                  // arguments
	)
	tasking.FailOnError(err, "Failed to bind queue")


	log.Printf("Connected to Rabbit on channels %s and %s\n", rabbitQueue.Name, rabbitQueueLong.Name)
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
	ticketKeys = make(map[string]*rsa.PublicKey)
	readKeys()
	//log.Println(keys)

	// Connect to rabbitmq
	connectRabbit()

	// Setup the HTTP-listener
	initHTTP()
}
