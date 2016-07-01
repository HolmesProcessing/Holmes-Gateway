package gateway

import (
	"log"
	"os"
	"sync"
	"errors"
	"net/http"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/streadway/amqp"
	"../utils"
)

type config struct {
	HTTP            string
	SourcesKeysPath string
	TicketKeysPath  string
	RabbitURI       string
	RabbitUser      string
	RabbitPassword  string
	RabbitQueue     string
	RoutingKey      string
	Exchange        string
}


var conf *config
var keys map[string]*rsa.PrivateKey
var ticketKeys map[string]*rsa.PublicKey
var keysMutex = &sync.Mutex{}
var rabbitChannel *amqp.Channel
var rabbitQueue amqp.Queue

func decryptTicket(enc *tasking.Encrypted) (string, error) {
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

func handleDecrypted(ticketStr string) (error) {
	var ticket tasking.Ticket
	err := json.Unmarshal([]byte(ticketStr), &ticket)
	if err != nil {
		return err
	}

	// Check ticket for validity
	signKey, found := ticketKeys[ticket.SignerKeyId]
	if !found {
		return errors.New("Couldn't verify signature: Key unknown")
	}
	err = tasking.VerifyTicket(ticket, signKey)
	if err != nil {
		log.Println("Ticket invalid!")
		return err
	}
	log.Println("Signature OK!")
	// Signature is OK

	//TODO: Check expired
	//TODO: Check ACL

	// Check for required fields; Check whether strings are in printable ascii-range
	for i := 0; i < len(ticket.Tasks); i++ {
		t := ticket.Tasks[i]
		log.Printf("Validating %+v\n", t)
		if t.PrimaryURI == "" || !stringPrintable(t.PrimaryURI) {
			return errors.New("Invalid Task (PrimaryURI invalid)")
		}
		if !stringPrintable(t.SecondaryURI) {
			return errors.New("Invalid Task (SecondaryURI invalid)")
		}
		if t.Filename == "" || !stringPrintable(t.Filename) {
			return errors.New("Invalid Task (Filename invalid)")
		}
		if len(t.Tasks) == 0 {
			return errors.New("Invalid Task")
		}
		for k := range t.Tasks {
			if k == "" || !stringPrintable(k) {
				return errors.New("Invalid Task")
			}
		}
		for j := 0; j < len(t.Tags); j++ {
			if !stringPrintable(t.Tags[j]) {
				return errors.New("Invalid Task (Tag invalid)")
			}
		}
		if t.Attempts < 0 {
			return errors.New("Invalid Task (Negative number of attempts)")
		}

		pushToTransport(t)
	}

	return err
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
	log.Printf("Marshalled: %s\n", msgBody)
	err = rabbitChannel.Publish(
		conf.Exchange,    // exchange
		conf.RoutingKey,  // key
		false,            // mandatory
		false,            // immediate
		amqp.Publishing {DeliveryMode: amqp.Persistent, ContentType: "text/plain", Body: msgBody,}) //msg
	if err != nil {
		log.Println("Error while pushing to transport: ", err)
		return
	}
}

func handleIncoming(task *tasking.Encrypted) (error){
	decTicket, err := decryptTicket(task)
	if err != nil {
		log.Println("Error while decrypting: ", err)
		return err
	}
	log.Println("Decrypted ticket:", decTicket)
	err = handleDecrypted(decTicket)
	if err != nil {
		log.Println("Error: ", err)
		return err
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

	handleIncoming(task)
	// TODO: Send an answer (fail/success)
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
			key, name := tasking.LoadPrivateKey(name)
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
			key, name := tasking.LoadPublicKey(name)
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
	ticketKeys = make(map[string]*rsa.PublicKey)
	readKeys()
	//log.Println(keys)

	// Connect to rabbitmq
	connectRabbit()

	// Setup the HTTP-listener
	initHTTP()
}
