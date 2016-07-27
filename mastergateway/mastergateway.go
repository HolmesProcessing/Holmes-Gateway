package mastergateway

import (
	"os"
	"io"
	"log"
	"sync"
	"time"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"net/http/httputil"
	"crypto/rsa"
	"crypto/rand"
	"encoding/json"
	"encoding/base64"
	"../utils"
)

type config struct {
	HTTP                string // The HTTP-binding for listening (IP+Port)
	SourcesKeysPath     string // Path to the public keys of the sources
	TicketSignKeyPath   string // Path to the private key used for signing tickets
	Organizations []tasking.Organization // All the known organizations
	StorageURI          string // URI of HolmesStorage
}

var (
	conf *config                               // The configuration struct
	keys map[string]*rsa.PublicKey             // The public keys of the sources
	keysMutex = &sync.Mutex{}                  // Mutex for the map, since keys could change during runtime
	ticketSignKey *rsa.PrivateKey              // The private key used for signing tickets
	ticketSignKeyName string                   // The id of the private key used for signing tickets
	srcRouter map[string]*tasking.Organization // Which source should be routed to which organization
	storageURI url.URL                        // The URL to storage for redirecting object-storage requests
	proxy *httputil.ReverseProxy               // The proxy object for redirecting object-storage requests
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

func requestTaskList(uri string, encryptedTicket *tasking.Encrypted, symKey []byte) (error, []byte) {
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
	tskerrors, _ := ioutil.ReadAll(resp.Body)
	encryptedTicket.IV[0] ^= 1
	tskerrorsDec, _ := tasking.AesDecrypt(tskerrors, symKey, encryptedTicket.IV)
	log.Printf("Received: %+v\n", string(tskerrorsDec))
	return err, tskerrorsDec
}

func handleTask(tasksStr string) (error, []tasking.TaskError) {
	tskerrors := make([]tasking.TaskError, 0)
	// TODO: Authenticate Request and check ACL!
	var tasks []tasking.Task
	log.Println("Task: ", tasksStr)
	err := json.Unmarshal([]byte(tasksStr), &tasks)
	if err != nil {
		log.Println("Error while unmarshalling tasks: ", err)
		return err, tskerrors
	}

	// Sort the tasks for their destination organizations, based on the
	// source of the task and the srcRouter-configuration
	tasklists := make(map[*tasking.Organization][]tasking.Task)
	for _,task := range tasks {
		org, found := srcRouter[task.Source]
		if !found {
			log.Printf("No route for source %s!\n", task.Source)
			tskerrors = append(tskerrors, tasking.TaskError{
				TaskStruct : task,
				Error : tasking.MyError{Error: errors.New("No route for source!")}})
			continue
		}
		tasklist, found := tasklists[org]
		// TODO: Is this efficient?
		if !found {
			tasklists[org] = []tasking.Task{task}
		} else {
			tasklists[org] = append(tasklist, task)
		}
	}

	for org, tasklist := range tasklists {
		err, tskOrgErrors := sendTaskList(tasklist, org)
		if err != nil {
			log.Println("Error while sending tasks: ", err)
		}
		var tskOrgErrorsP []tasking.TaskError
		err = json.Unmarshal(tskOrgErrors, &tskOrgErrorsP)
		if err != nil {
			log.Printf("Error while parsing result")
		}
		// TODO: handle answer
		tskerrors = append(tskerrors, tskOrgErrorsP...)
	}
	// TODO: collect tskerrors and return them
	return nil, tskerrors
}

func sendTaskList(tasks []tasking.Task, org *tasking.Organization) (error, []byte){
	uri := org.Uri

	// Retrieve the corresponding public key
	// Note: Since this is all destined for the same organization and
	// the organization is supposed to have access to all the sources
	// for tasks in this tasklist, we just use the source of the first
	// one for the encryption-key
	asymKeyId := tasks[0].Source

	// Choose AES-key and IV
	symKey := make([]byte, 16) //TODO: Length 16 OK?
	if _, err := io.ReadFull(rand.Reader, symKey); err != nil {
		log.Println("Error while creating AES-key: ", err)
		return err, nil
	}
	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Println("Error while creating IV: ", err)
		return err, nil
	}

	ticket, err := createTicket(tasks)
	if err != nil {
		log.Println("Error while creating Ticket: ", err)
		return err, nil
	}

	ticketM, err := json.Marshal(ticket)
	if err != nil {
		log.Println("Error while Marshalling ticket: ", err)
		return err, nil
	}

	// Encrypt the ticket and the AES-key
	et, err := encryptTicket(ticketM, asymKeyId, symKey, iv)
	if err != nil {
		log.Println("Error while encrypting: ", err)
		return err, nil
	}
	// Issue HTTP-GET-Request
	err, tskerrors := requestTaskList(uri, et, symKey)
	if err != nil {
		log.Println("Error requesting task: ", err)
		return err, tskerrors
	}
	return err, tskerrors
}

func readKeys() {
	tasking.LoadKeysAndWatch(conf.SourcesKeysPath, ".pub",
		func(name string){
			keysMutex.Lock()
			delete(keys, name)
			keysMutex.Unlock()
			log.Println(keys)
		},
		func(name string){
			key, name, err := tasking.LoadPublicKey(name)
			if err != nil {
				log.Printf("Error reading key (%s):%s\n", name, err)
				return
			}

			keysMutex.Lock()
			keys[name] = key
			keysMutex.Unlock()
			log.Println(keys)
		})
	var err error
	ticketSignKey, ticketSignKeyName, err = tasking.LoadPrivateKey(conf.TicketSignKeyPath)
	if err != nil {
		log.Fatal("Error while reading key for signing (%s):%s", ticketSignKeyName, err)
	}
}

func httpRequestIncomingTask(w http.ResponseWriter, r *http.Request) {
	task := r.FormValue("task")
	err, tskerrors := handleTask(task)
	if err != nil {
		log.Println(err)
		w.Write([]byte(err.Error()+"\n"))
	} else if len(tskerrors) != 0 {
		// TODO: For automatical decoding it might be better to Marshal the whole slice
		// instead of the individual elements
		//x, _ := json.Marshal(tskerrors)
		//w.Write(x)
		for _, j := range(tskerrors) {
			x, _ := json.Marshal(j)
			w.Write(x)
			w.Write([]byte("\n\n"))
		}
	}
}

func httpRequestIncomingSample(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	*r.URL = storageURI
    proxy.ServeHTTP(w, r)
}

func initHTTP() {
	http.HandleFunc("/task/", httpRequestIncomingTask)
	storageURI, _ := url.Parse(conf.StorageURI)
	proxy = httputil.NewSingleHostReverseProxy(storageURI)
	http.HandleFunc("/samples/", httpRequestIncomingSample)
	log.Printf("Listening on %s\n", conf.HTTP)
	log.Fatal(http.ListenAndServe(conf.HTTP, nil))
}

func initSourceRouting() {
	//TODO: make this dynamically configurable
	srcRouter = make(map[string]*tasking.Organization)
	log.Println("=====")
	for num, org := range(conf.Organizations) {
		log.Println(org)
		for _, src := range(org.Sources) {
			srcRouter[src] = &conf.Organizations[num]
		}
	}
	log.Println("=====")
	log.Println(srcRouter)	
}

func Start(confPath string) {
	// Parse the configuration
	conf = &config{}
	cfile, _ := os.Open(confPath)
	err := json.NewDecoder(cfile).Decode(&conf)
	tasking.FailOnError(err, "Couldn't read config file")

	initSourceRouting()
	
	// Parse the public keys
	keys = make(map[string]*rsa.PublicKey)
	readKeys()
	//log.Println(keys)

	// Setup the HTTP-listener
	initHTTP()
}
