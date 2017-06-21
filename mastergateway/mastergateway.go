package mastergateway

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/HolmesProcessing/Holmes-Gateway/utils"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type config struct {
	HTTP                 string                 // The HTTP-binding for listening (IP+Port)
	SourcesKeysPath      string                 // Path to the public keys of the sources
	TicketSignKeyPath    string                 // Path to the private key used for signing tickets
	Organizations        []tasking.Organization // All the known organizations
	OwnOrganization      string                 // The name of the own organization (Should also be present in the list "Organizations")
	StorageURI           string                 // URI of HolmesStorage
	DisableStorageVerify bool
	AutoTasks            map[string](map[string][]string) // Tasks that should be automatically executed on new objects mimetype -> taskname -> args
	MaxUploadSize        uint32                           // The maximum size of a sample-upload in Megabyte
	CertificatePath      string
	CertificateKeyPath   string
	AllowedUsers         []tasking.User
}

var (
	conf              *config                            // The configuration struct
	keys              map[string]*rsa.PublicKey          // The public keys of the sources
	keysMutex         = &sync.Mutex{}                    // Mutex for the map, since keys could change during runtime
	ticketSignKey     *rsa.PrivateKey                    // The private key used for signing tickets
	ticketSignKeyName string                             // The id of the private key used for signing tickets
	srcRouter         map[string][]*tasking.Organization // Which source should be routed to which organization
	ownOrganization   *tasking.Organization              // Pointer to the own organization in the list of organizations
	storageURI        url.URL                            // The URL to storage for redirecting object-storage requests
	proxy             *httputil.ReverseProxy             // The proxy object for redirecting object-storage requests
	users             map[string]*tasking.User           // Map: Username -> User-struct (TODO: Move to storage)
)

func createTicket(tasks []tasking.Task) (tasking.Ticket, error) {
	t := tasking.Ticket{
		Expiration:  time.Now().Add(3 * time.Hour), //TODO: 3 Hours validity reasonable?
		Tasks:       tasks,
		SignerKeyId: ticketSignKeyName,
		Signature:   nil}
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
	encryptedTicket := tasking.Encrypted{
		KeyFingerprint: asymKeyId,
		EncryptedKey:   encKey,
		Encrypted:      encrypted,
		IV:             iv}
	return &encryptedTicket, err
}

func requestTaskList(uri string, encryptedTicket *tasking.Encrypted, symKey []byte) (error, []byte) {
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return err, nil
	}
	q := req.URL.Query()
	q.Add("KeyFingerprint", encryptedTicket.KeyFingerprint)
	q.Add("EncryptedKey", base64.StdEncoding.EncodeToString(encryptedTicket.EncryptedKey))
	q.Add("IV", base64.StdEncoding.EncodeToString(encryptedTicket.IV))
	q.Add("Encrypted", base64.StdEncoding.EncodeToString(encryptedTicket.Encrypted))
	req.URL.RawQuery = q.Encode()
	log.Println(req.URL)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err, nil
	}
	answer, _ := ioutil.ReadAll(resp.Body)
	encryptedTicket.IV[0] ^= 1
	answerDec, _ := tasking.AesDecrypt(answer, symKey, encryptedTicket.IV)
	log.Printf("Decrypted: %+v\n", string(answerDec))
	return err, answerDec
}

func authenticate(username string, password string) (*tasking.User, error) {
	// TODO: Ask storage instead of configuration file for credentials
	user, exists := users[username]
	if !exists {
		// compare some dummy value to prevent timing based attack
		bcrypt.CompareHashAndPassword([]byte("$2a$06$fLcXyZd6xs60iPj8sBXf8exGfcIMnxZWHH5Eyf1.fwkSnuNq0h6Aa"), []byte(password))
		log.Println("User does not exist")
		return nil, errors.New("Authentication failed")
	}
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		log.Printf("\x1b[0;31m%s\x1b[0m\n", err)
		return nil, errors.New("Authentication failed")
	} else {
		log.Printf("Authenticated as %s\n", username)
	}
	return user, nil
}

func handleTask(tasksStr string, username string, password string) (error, []tasking.TaskError) {
	tskerrors := make([]tasking.TaskError, 0)
	// TODO: Maybe we want to store the UID in the task
	_, err := authenticate(username, password)
	if err != nil {
		return err, nil
	}
	var tasks []tasking.Task
	log.Println("Task: ", tasksStr)
	err = json.Unmarshal([]byte(tasksStr), &tasks)
	if err != nil {
		log.Println("Error while unmarshalling tasks: ", err)
		return err, tskerrors
	}

	// Submit all the tasks, until either all of them are either accepted
	// or unrecoverable rejected
	unrecoverableErrors := make([]tasking.TaskError, 0, len(tasks))
	iteration := 0
	for len(tasks) > 0 {
		tskerrors = tskerrors[0:0]
		log.Printf("\x1b[0;32mSending tasks try #%d\x1b[0m\n", iteration)

		// Sort the tasks based on their sources
		tasklists := make(map[string][]tasking.Task)
		for _, task := range tasks {
			tasklist, found := tasklists[task.Source]
			if !found {
				tasklists[task.Source] = []tasking.Task{task}
			} else {
				tasklists[task.Source] = append(tasklist, task)
			}
		}

		// Send the tasks and handle the answers
		for source, tasklist := range tasklists {
			orgs, found := srcRouter[source]
			if !found {
				for _, task := range tasklist {
					log.Printf("No route for source %s!\n", task.Source)
					unrecoverableErrors = append(unrecoverableErrors, tasking.TaskError{
						TaskStruct: task,
						Error:      tasking.MyError{Error: errors.New("No route for source!")}})
				}
				continue
			}
			if len(orgs) <= iteration {
				for _, task := range tasklist {
					unrecoverableErrors = append(unrecoverableErrors, tasking.TaskError{
						TaskStruct: task,
						Error:      tasking.MyError{Error: errors.New("Task rejected by all organizations!")}})
				}
				continue
			}
			org := orgs[iteration]

			err, answerString := sendTaskList(tasklist, org)
			if err != nil {
				log.Println("Error while sending tasks: ", err)
				for task := range tasklist {
					tskerrors = append(tskerrors, tasking.TaskError{
						TaskStruct: tasklist[task],
						Error:      tasking.MyError{Error: errors.New("Error while sending task! " + err.Error())}})
				}
				continue
			}
			var answer tasking.GatewayAnswer
			err = json.Unmarshal(answerString, &answer)
			if err != nil {
				log.Printf("Error while parsing result")
				for task := range tasklist {
					tskerrors = append(tskerrors, tasking.TaskError{
						TaskStruct: tasklist[task],
						Error:      tasking.MyError{Error: errors.New("Error while parsing result! " + err.Error())}})
				}
				continue

			} else if answer.Error != nil {
				log.Printf("Error: ", answer.Error)
				for task := range tasklist {
					tskerrors = append(tskerrors, tasking.TaskError{
						TaskStruct: tasklist[task],
						Error:      *answer.Error,
					})
				}
				continue
			}
			tskerrors = append(tskerrors, answer.TskErrors...)
		}
		// go through list of tskerrors and reissue those with a recoverable error-code
		log.Printf("\x1b[0;33mreceived errors: %+v\x1b[0m", tskerrors)
		iteration += 1
		tasks = make([]tasking.Task, 0, len(tskerrors))
		for _, e := range tskerrors {
			switch e.Error.Code {
			case tasking.ERR_OTHER_UNRECOVERABLE, tasking.ERR_TASK_INVALID:
				// These tasks are not recoverable and won't be reissued
				unrecoverableErrors = append(unrecoverableErrors, e)
				break
			default:
				tasks = append(tasks, e.TaskStruct)
			}
		}
	}
	log.Printf("\x1b[0;31mUnrecoverable Errors: %+v\x1b[0m", unrecoverableErrors)

	return nil, unrecoverableErrors
}

func sendTaskList(tasks []tasking.Task, org *tasking.Organization) (error, []byte) {
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
	err, answer := requestTaskList(uri, et, symKey)
	if err != nil {
		log.Println("Error requesting task: ", err)
		return err, answer
	}
	return err, answer
}

func readKeys() {
	tasking.LoadKeysAndWatch(conf.SourcesKeysPath, ".pub",
		func(name string) {
			keysMutex.Lock()
			delete(keys, name)
			keysMutex.Unlock()
			log.Println(keys)
		},
		func(name string) {
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
		log.Fatal("Error while reading key for signing ("+ticketSignKeyName+"):", err)
	}
}

func httpRequestIncomingTask(w http.ResponseWriter, r *http.Request) {
	task := r.FormValue("task")
	username := r.FormValue("username")
	password := r.FormValue("password")
	err, tskerrors := handleTask(task, username, password)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), 500)
	} else if len(tskerrors) != 0 {
		// TODO: For automatical decoding it might be better to Marshal the whole slice
		// instead of the individual elements. For readability, here every element is
		// individually marshalled and newlines are appended.
		//x, _ := json.Marshal(tskerrors)
		//w.Write(x)
		for _, j := range tskerrors {
			x, _ := json.Marshal(j)
			w.Write(x)
			w.Write([]byte("\n\n"))
		}
	}
}

type myTransport struct {
}

type storageResult struct {
	Type             string    `json:"type"`
	CreationDateTime time.Time `json:"creation_date_time"`
	Submissions      []string  `json:"submissions"`
	Source           []string  `json:"source"`

	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`

	FileMime string   `json:"file_mime"`
	FileName []string `json:"file_name"`

	DomainFQDN      string `json:"domain_fqdn"`
	DomainTLD       string `json:"domain_tld"`
	DomainSubDomain string `json:"domain_sub_domain"`

	IPAddress string `json:"ip_address"`
	IPv6      bool   `json:"ip_v6"`

	EmailAddress       string `json:"email_address"`
	EmailLocalPart     string `json:"email_local_part"`
	EmailDomainPart    string `json:"email_domain_part"`
	EmailSubAddressing string `json:"email_sub_addressing"`

	GenericIdentifier     string `json:"generic_identifier"`
	GenericType           string `json:"generic_type"`
	GenericDataRelAddress string `json:"generic_data_rel_address"`
}

type storageResponse struct {
	ResponseCode int
	Failure      string
	Result       storageResult
}

func (t *myTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	// Since accessing the Form-values of the request changes the reader,
	// which cannot be rewinded / seeked, an error would be thrown, if the
	// request was forwarded with the reader at the wrong position.
	// For this reason, the whole body is read and a new reader is created,
	// which can be rewinded.
	var err error
	if request.ContentLength > 1024*1024*int64(conf.MaxUploadSize) {
		respBody := ioutil.NopCloser(bytes.NewBufferString("Upload too large"))
		resp := &http.Response{StatusCode: 413, Body: respBody}
		respBody.Close()
		log.Println("Upload too large")
		return resp, nil
	}

	var reqbuf []byte
	if request.ContentLength > 0 {
		reqbuf = make([]byte, request.ContentLength)
		_, err = io.ReadFull(request.Body, reqbuf)
		if err != nil {
			log.Printf("Error reading body!", err)
			return nil, err
		}
	} else {
		log.Println("ContentLength is negative...")
		reqbuf, err = ioutil.ReadAll(request.Body)
		if err != nil {
			log.Printf("Error reading body!", err)
			return nil, err
		}
	}

	reader := bytes.NewReader(reqbuf)
	reqrdr := ioutil.NopCloser(reader)
	request.Body = reqrdr

	defer func() {
		request.Body.Close()
		reqrdr.Close()
	}()

	request.ParseMultipartForm(1024 * 1024 * int64(conf.MaxUploadSize))
	// Read the name and the source from the request, because they can not be
	// reconstructed from storage's response.
	name := request.FormValue("name")
	source := request.FormValue("source")

	username := request.FormValue("username")
	password := request.FormValue("password")

	// restore the reader for the body
	reader.Seek(0, 0)

	user, err := authenticate(username, password)
	if err != nil {
		return nil, err
	}

	request.URL, err = url.Parse(request.URL.String() + "api/v2/raw_data/")

	form, _ := url.ParseQuery(request.URL.RawQuery)
	form.Set("user_id", strconv.Itoa(user.Id))
	request.URL.RawQuery = form.Encode()

	// Do the proxy-request
	trans := http.DefaultTransport.(*http.Transport)
	// If you want to disable certificate validation, uncomment this line
	trans.TLSClientConfig = &tls.Config{InsecureSkipVerify: conf.DisableStorageVerify}

	response, err := trans.RoundTrip(request)
	if err != nil {
		log.Printf("Error performing proxy-request!", err)
		return nil, err
	}

	if response.StatusCode != 200 {
		log.Printf("Error: Received %d\n", response.StatusCode)
		return response, err
	}
	// Parse the response. If it was successful, execute automatic tasks
	var resp storageResponse
	log.Printf("%+v\n", response)
	var buf []byte
	if response.ContentLength > 0 {
		buf = make([]byte, response.ContentLength)
		_, err = io.ReadFull(response.Body, buf)
		if err != nil {
			log.Printf("Error reading body!", err)
			return nil, err
		}
	} else {
		log.Println("ContentLength is negative...")
		buf, err = ioutil.ReadAll(response.Body)
		if err != nil {
			log.Printf("Error reading body!", err)
			return nil, err
		}
	}
	rdr := ioutil.NopCloser(bytes.NewReader(buf))
	defer func() {
		rdr.Close()
		response.Body.Close()
	}()
	json.Unmarshal(buf, &resp)

	if resp.ResponseCode == 0 {
		log.Printf("\x1b[0;32mSuccessfully uploaded sample with SHA256: %s\x1b[0m", resp.Result.SHA256)
		// Execute automatic tasks
		for t := range conf.AutoTasks {
			if strings.Contains(resp.Result.FileMime, t) {
				autotasks := conf.AutoTasks[t]
				if len(autotasks) != 0 {
					task := tasking.Task{
						PrimaryURI:   resp.Result.SHA256,
						SecondaryURI: "",
						Filename:     name,
						Tasks:        autotasks,
						Tags:         []string{},
						Attempts:     0,
						Source:       source,
						Download:     true,
					}

					log.Printf("\x1b[0;33mAutomatically executing %+v\x1b[0m\n", task)
					sendTaskList([]tasking.Task{task}, ownOrganization)
				}
			}
		}
	} else {
		log.Printf("\x1b[0;31mUpload failed\x1b[0m\n")
	}

	// restore the reader for the body
	response.Body = rdr
	return response, err
}

func httpRequestIncomingSample(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL)
	*r.URL = storageURI

	proxy.ServeHTTP(w, r)
}

func initHTTP() {
	// build a secure tls configuration for the http server
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	// necessary to enable strict transport security via header
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "origin, content-type, accept")
		w.Header().Set("Content-Type", "application/json")

		w.Write([]byte("Holmes-Mastergateway.\n"))
	})

	// productive routes
	mux.HandleFunc("/task/", httpRequestIncomingTask)
	mux.HandleFunc("/samples/", httpRequestIncomingSample)

	// storage proxy
	storageURI, _ := url.Parse(conf.StorageURI)
	proxy = httputil.NewSingleHostReverseProxy(storageURI)
	proxy.Transport = &myTransport{}

	// server settings
	srv := &http.Server{
		Addr:         conf.HTTP,
		Handler:      mux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	log.Printf("Listening on %s\n", conf.HTTP)
	log.Fatal(srv.ListenAndServeTLS(conf.CertificatePath, conf.CertificateKeyPath))
}

func initSourceRouting() {
	//TODO: make this dynamically configurable
	ownOrganization = nil
	srcRouter = make(map[string][]*tasking.Organization)

	log.Println("=====")
	for num, org := range conf.Organizations {
		log.Println(org)
		for _, src := range org.Sources {
			routes, exists := srcRouter[src]
			if !exists {
				srcRouter[src] = []*tasking.Organization{&conf.Organizations[num]}
			} else {
				srcRouter[src] = append(routes, &conf.Organizations[num])
			}
		}
		if org.Name == conf.OwnOrganization {
			ownOrganization = &conf.Organizations[num]
		}
	}
	log.Println("=====")
	log.Println(srcRouter)
	if ownOrganization == nil {
		log.Fatal("Own organization was not found")
	}
}

func initUsers() {
	users = make(map[string]*tasking.User)
	for u := range conf.AllowedUsers {
		user := &(conf.AllowedUsers[u])
		users[user.Name] = user
	}
}

func Start(confPath string) {
	// Parse the configuration
	conf = &config{MaxUploadSize: 200}
	cfile, _ := os.Open(confPath)
	err := json.NewDecoder(cfile).Decode(&conf)
	tasking.FailOnError(err, "Couldn't read config file")

	initSourceRouting()
	initUsers()

	// Parse the public keys
	keys = make(map[string]*rsa.PublicKey)
	readKeys()
	//log.Println(keys)

	// Setup the HTTP-listener
	initHTTP()
}
