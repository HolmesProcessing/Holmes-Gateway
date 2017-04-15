package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"github.com/streadway/amqp"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type TaskRequest struct {
	PrimaryURI   string              `json:"primaryURI"`
	SecondaryURI string              `json:"secondaryURI"`
	Filename     string              `json:"filename"`
	Tasks        map[string][]string `json:"tasks"`
	Tags         []string            `json:"tags"`
	Attempts     int                 `json:"attempts"`
	Source       string              `json:"source"`
	Download     bool                `json:"download"`
	Comment      string              `json:"comment"`
}

type Organization struct {
	Name    string
	Uri     string
	Sources []string
}

type User struct {
	Name         string `json:"name"`
	Id           int    `json:"id"`
	PasswordHash string `json:"pw"`
}

type ErrCode int

const (
	ERR_NONE                ErrCode = 1 + iota
	ERR_KEY_UNKNOWN                 = iota
	ERR_ENCRYPTION                  = iota
	ERR_TASK_INVALID                = iota
	ERR_NOT_ALLOWED                 = iota
	ERR_OTHER_UNRECOVERABLE         = iota
	ERR_OTHER_RECOVERABLE           = iota
)

type MyError struct {
	Error error
	Code  ErrCode
}

type TaskError struct {
	TaskStruct TaskRequest
	Error      MyError
}

type GatewayAnswer struct {
	Error     *MyError
	TskErrors []TaskError
}

func (me MyError) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		struct {
			Error string
			Code  ErrCode
		}{
			Error: me.Error.Error(),
			Code:  me.Code,
		})
}

func (me *MyError) UnmarshalJSON(data []byte) error {
	var s struct {
		Error string
		Code  ErrCode
	}
	err := json.Unmarshal(data, &s)
	me.Error = errors.New(s.Error)
	me.Code = s.Code
	return err
}

func FailOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}

type AMQPConf struct {
	Queue      string
	Exchange   string
	RoutingKey string
}

type config struct {
	HTTP               string                           // The HTTP-binding for listening (IP+Port)
	Organizations      []Organization                   // All the known organizations
	OwnOrganization    string                           // The name of the own organization (Should also be present in the list "Organizations")
	StorageSampleURI   string                           // URI of HolmesStorage
	AutoTasks          map[string](map[string][]string) // Tasks that should be automatically executed on new objects mimetype -> taskname -> args
	MaxUploadSize      uint32                           // The maximum size of a sample-upload in Megabyte
	CertificatePath    string
	CertificateKeyPath string
	AllowedUsers       []User

	AMQP          string
	AMQPDefault   AMQPConf
	AMQPSplitting map[string]AMQPConf
}

var (
	conf            *config                    // The configuration struct
	srcRouter       map[string][]*Organization // Which source should be routed to which organization
	ownOrganization *Organization              // Pointer to the own organization in the list of organizations
	storageURI      url.URL                    // The URL to storage for redirecting object-storage requests
	proxy           *httputil.ReverseProxy     // The proxy object for redirecting object-storage requests
	users           map[string]*User           // Map: Username -> User-struct (TODO: Move to storage)

	AMQPChannel *amqp.Channel
)

func requestTaskList(tasks []TaskRequest, org *Organization) (error, []byte) {
	req, err := http.NewRequest("GET", org.Uri, nil)
	if err != nil {
		return err, nil
	}
	tasks_json, err := json.Marshal(tasks)
	if err != nil {
		return err, nil
	}
	q := req.URL.Query()
	q.Add("task", string(tasks_json))
	req.URL.RawQuery = q.Encode()
	log.Println(req.URL)
	//TODO: REMOVE!!!
	//tr := &http.Transport{}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return err, nil
	}
	answer, err := ioutil.ReadAll(resp.Body)
	log.Printf("Received: %+v\n", string(answer))
	if err != nil {
		log.Println("Error requesting task: ", err)
	}
	return err, answer
}

type myTransport struct {
}

type storageResult struct {
	Sha256      string
	Sha1        string
	Md5         string
	Mime        string
	Source      []string
	Objname     []string `json:obj_name`
	Submissions []string
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
	reqbuf := make([]byte, request.ContentLength)
	_, err = io.ReadFull(request.Body, reqbuf)
	if err != nil {
		log.Printf("Error reading body!", err)
		return nil, err
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

	form, _ := url.ParseQuery(request.URL.RawQuery)
	form.Set("user_id", strconv.Itoa(user.Id))
	request.URL.RawQuery = form.Encode()
	// Do the proxy-request
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		log.Printf("Error performing proxy-request!", err)
		return nil, err
	}

	// Parse the response. If it was successful, execute automatic tasks
	var resp storageResponse
	buf := make([]byte, response.ContentLength)

	_, err = io.ReadFull(response.Body, buf)
	if err != nil {
		log.Printf("Error reading body!", err)
		return nil, err
	}
	rdr := ioutil.NopCloser(bytes.NewReader(buf))
	defer func() {
		rdr.Close()
		response.Body.Close()
	}()
	json.Unmarshal(buf, &resp)
	//log.Printf("%+v\n", resp)
	if resp.ResponseCode == 1 {
		log.Printf("\x1b[0;32mSuccessfully uploaded sample with SHA256: %s\x1b[0m", resp.Result.Sha256)
		// Execute automatic tasks
		for t := range conf.AutoTasks {
			if strings.Contains(resp.Result.Mime, t) {
				autotasks := conf.AutoTasks[t]
				if len(autotasks) != 0 {
					task := TaskRequest{
						PrimaryURI:   resp.Result.Sha256,
						SecondaryURI: "",
						Filename:     name,
						Tasks:        autotasks,
						Tags:         []string{},
						Attempts:     0,
						Source:       source,
						Download:     true,
					}

					log.Printf("\x1b[0;33mAutomatically executing %+v\x1b[0m\n", task)
					requestTaskList([]TaskRequest{task}, ownOrganization)
				}
			}
		}
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

func handleTask(tasks []TaskRequest, username string, password string) (error, []TaskError) {
	tskerrors := make([]TaskError, 0)
	// TODO: Maybe we want to store the UID in the task
	_, err := authenticate(username, password)
	if err != nil {
		return err, nil
	}

	// Submit all the tasks, until all of them are either accepted
	// or unrecoverably rejected
	unrecoverableErrors := make([]TaskError, 0, len(tasks))
	iteration := 0
	for len(tasks) > 0 {
		tskerrors = tskerrors[0:0]
		log.Printf("\x1b[0;32mSending tasks try #%d\x1b[0m\n", iteration)

		// Sort the tasks based on their sources
		tasklists := make(map[string][]TaskRequest)
		for _, task := range tasks {
			tasklist, found := tasklists[task.Source]
			if !found {
				tasklists[task.Source] = []TaskRequest{task}
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
					unrecoverableErrors = append(unrecoverableErrors, TaskError{
						TaskStruct: task,
						Error:      MyError{Error: errors.New("No route for source!")}})
				}
				continue
			}
			if len(orgs) <= iteration {
				for _, task := range tasklist {
					unrecoverableErrors = append(unrecoverableErrors, TaskError{
						TaskStruct: task,
						Error:      MyError{Error: errors.New("Task rejected by all organizations!")}})
				}
				continue
			}

			var answer GatewayAnswer
			// send the tasks to the given organization and parse the answer
			var org *Organization
			org = orgs[iteration]
			if org == ownOrganization {
				err, tskerrors := handleOwnTasks(tasklist)
				answer = GatewayAnswer{
					Error:     err,
					TskErrors: tskerrors,
				}
			} else {
				err, answerString := requestTaskList(tasklist, org)
				if err != nil {
					log.Println("Error while sending tasks: ", err)
					for task := range tasklist {
						tskerrors = append(tskerrors, TaskError{
							TaskStruct: tasklist[task],
							Error:      MyError{Error: errors.New("Error while sending task! " + err.Error())}})
					}
					continue
				}
				err = json.Unmarshal(answerString, &answer)
				if err != nil {
					log.Printf("Error while parsing result", err)
					for task := range tasklist {
						tskerrors = append(tskerrors, TaskError{
							TaskStruct: tasklist[task],
							Error:      MyError{Error: errors.New("Error while parsing result! " + err.Error())}})
					}
					continue

				}
			}

			// The answer contained an error
			if answer.Error != nil {
				log.Printf("Error: ", answer.Error)
				for task := range tasklist {
					tskerrors = append(tskerrors, TaskError{
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
		tasks = make([]TaskRequest, 0, len(tskerrors))
		for _, e := range tskerrors {
			switch e.Error.Code {
			case ERR_OTHER_UNRECOVERABLE, ERR_TASK_INVALID:
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

func stringPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		c := int(s[i])
		if c < 0x9 || (c > 0x0d && c < 0x20) || (c > 0x7e) {
			return false
		}
	}
	return true
}

func checkTask(task *TaskRequest) error {
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
	if !stringPrintable(task.Comment) {
		return errors.New("Invalid Task (Comment invalid)")
	}
	return nil
}

func pushToAMQP(task *TaskRequest, aconf *AMQPConf) *MyError {
	msgBody, err := json.Marshal(task)
	if err != nil {
		log.Println("Error while Marshalling: ", err)
		return &MyError{Error: err, Code: ERR_OTHER_RECOVERABLE}
	}
	pub := amqp.Publishing{DeliveryMode: amqp.Persistent, ContentType: "text/plain", Body: msgBody}
	log.Printf("Pushing to %s: \x1b[0;32m%s\x1b[0m\n", aconf.Exchange, msgBody)
	err = AMQPChannel.Publish(aconf.Exchange, aconf.RoutingKey, false, false, pub)

	if err != nil {
		log.Println("Error while pushing to transport: ", err)
		// try to recover three times
		try := 0
		for try < 3 {
			try++
			log.Println("Trying to restore the connection... #", try)
			err = connectAMQP()
			if err == nil {
				break
			}
			// sleep 3 seconds
			time.Sleep(time.Duration(3000000000))
		}
		if err != nil {
			// could not recover the connection after third try => give up
			return &MyError{Error: err, Code: ERR_OTHER_RECOVERABLE}
		}
		log.Println("Connection restored")

		// retry pushing
		err = AMQPChannel.Publish(aconf.Exchange, aconf.RoutingKey, false, false, pub)
		if err != nil {
			return &MyError{Error: err, Code: ERR_OTHER_RECOVERABLE}
		}
	}
	return nil
}

func pushToTransport(task TaskRequest) *MyError {
	// Splits the task-request into services and pushes them to their corresponding queues
	log.Printf("%+v\n", task)

	// split task:
	tasks := task.Tasks

	// since each task (e.g. CUCKOO, PEID, ...) can have a special destination defined
	// in the config we go trough all tasks in this task struct and check it.
	// If the task had a special destination we cut it out of the original task struct and
	// send it seperately.
	// If the task is sent using RabbitDefault we just leave it in the struct and send the
	// whole task struct after we went trough it completly.
	for t := range tasks {
		log.Println(t)

		// check if special routing is defined in the config
		rconf, exists := conf.AMQPSplitting[t]
		if !exists {
			continue
		}

		// build a seperate task struct
		task.Tasks = map[string][]string{t: tasks[t]}
		if err := pushToAMQP(&task, &rconf); err != nil {
			return err
		}

		// delete the task from the tasks list of the struct
		delete(tasks, t)
	}

	// If there are tasks left we send them all as one big pack to the default destination.
	if len(tasks) == 0 {
		return nil
	}

	task.Tasks = tasks
	if err := pushToAMQP(&task, &conf.AMQPDefault); err != nil {
		return err
	}

	return nil
}

func handleOwnTasks(tasks []TaskRequest) (*MyError, []TaskError) {
	// Handles tasks destined for the own organization
	tskerrors := make([]TaskError, 0)

	// Check for required fields; Check whether strings are in printable ascii-range
	for i := 0; i < len(tasks); i++ {
		task := tasks[i]
		e := checkTask(&task)
		if e != nil {
			e2 := MyError{Error: e, Code: ERR_TASK_INVALID}
			tskerrors = append(tskerrors, TaskError{
				TaskStruct: task,
				Error:      e2})
		} else {
			savedPrimaryURI := task.PrimaryURI
			savedSecondaryURI := task.SecondaryURI
			task.PrimaryURI = conf.StorageSampleURI + task.PrimaryURI
			if task.SecondaryURI != "" {
				task.SecondaryURI = conf.StorageSampleURI + task.SecondaryURI
			}
			myerr := pushToTransport(task)
			if myerr != nil {
				task.PrimaryURI = savedPrimaryURI
				task.SecondaryURI = savedSecondaryURI
				tskerrors = append(tskerrors, TaskError{
					TaskStruct: task,
					Error:      *myerr})
			}
		}
	}

	return nil, tskerrors
}

func httpRequestIncomingTask(w http.ResponseWriter, r *http.Request) {
	taskStr := r.FormValue("task")
	username := r.FormValue("username")
	password := r.FormValue("password")
	var tasks []TaskRequest
	log.Println("Task: ", taskStr)
	err := json.Unmarshal([]byte(taskStr), &tasks)
	if err != nil {
		log.Println("Error while unmarshalling tasks: ", err)
		http.Error(w, err.Error(), 500)
	}

	err, tskerrors := handleTask(tasks, username, password)
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

func httpRequestIncomingTaskForeign(w http.ResponseWriter, r *http.Request) {
	taskStr := r.FormValue("task")
	var tasks []TaskRequest
	log.Println("Task: ", taskStr)
	err := json.Unmarshal([]byte(taskStr), &tasks)
	if err != nil {
		log.Println("Error while unmarshalling tasks: ", err)
		http.Error(w, err.Error(), 500)
	}

	myerr, tskerrors := handleOwnTasks(tasks)
	answer := GatewayAnswer{
		Error:     myerr,
		TskErrors: tskerrors,
	}
	answer_json, _ := json.Marshal(answer)
	w.Write(answer_json)
	log.Println(string(answer_json))

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

		w.Write([]byte("Holmes-Gateway.\n"))
	})

	// productive routes
	mux.HandleFunc("/task/", httpRequestIncomingTask)
	mux.HandleFunc("/task_foreign/", httpRequestIncomingTaskForeign)
	mux.HandleFunc("/samples/", httpRequestIncomingSample)

	// storage proxy
	storageURI, _ := url.Parse(conf.StorageSampleURI)
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
	// Goes through all the organizations in the configuration-file, looks, what sources
	// they have, and creates the mapping srcRouter (source -> []organization)
	// Own organization is always first

	//TODO: make this dynamically configurable
	ownOrganization = nil
	srcRouter = make(map[string][]*Organization)

	log.Println("=====")
	for num, org := range conf.Organizations {
		log.Println(org)
		if org.Name == conf.OwnOrganization {
			ownOrganization = &conf.Organizations[num]
		}

		for _, src := range org.Sources {
			routes, exists := srcRouter[src]
			if !exists {
				srcRouter[src] = []*Organization{&conf.Organizations[num]}
			} else {
				if &org == ownOrganization {
					// prepend
					srcRouter[src] = append([]*Organization{&conf.Organizations[num]}, routes...)
				} else {
					// append
					srcRouter[src] = append(routes, &conf.Organizations[num])
				}
			}
		}
	}
	log.Println("=====")
	log.Println(srcRouter)
	if ownOrganization == nil {
		log.Fatal("Own organization was not found")
	}
}

func initUsers() {
	users = make(map[string]*User)
	for u := range conf.AllowedUsers {
		user := &(conf.AllowedUsers[u])
		users[user.Name] = user
	}
}

func authenticate(username string, password string) (*User, error) {
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

func addAMQPConf(c AMQPConf) error {
	queue, err := AMQPChannel.QueueDeclare(
		c.Queue, //name
		true,    // durable
		false,   // delete when unused
		false,   // exclusive
		false,   // no-wait
		nil,     // arguments
	)
	if err != nil {
		return errors.New("Failed to declare a queue: " + err.Error())
	}

	err = AMQPChannel.ExchangeDeclare(
		c.Exchange, // name
		"topic",    // type
		true,       // durable
		false,      // auto-deleted
		false,      // internal
		false,      // no-wait
		nil,        // arguments
	)
	if err != nil {
		return errors.New("Failed to declare an exchange: " + err.Error())
	}

	err = AMQPChannel.QueueBind(
		queue.Name,   // queue name
		c.RoutingKey, // routing key
		c.Exchange,   // exchange
		false,        // nowait
		nil,          // arguments
	)
	if err != nil {
		return errors.New("Failed to bind queue: " + err.Error())
	}
	return nil
}

func connectAMQP() error {
	conn, err := amqp.Dial(conf.AMQP)
	if err != nil {
		return errors.New("Failed to connect to AMQPMQ: " + err.Error())
	}
	//defer conn.Close()

	AMQPChannel, err = conn.Channel()
	if err != nil {
		return errors.New("Failed to open a channel: " + err.Error())
	}
	//defer AMQPChannel.Close()
	addAMQPConf(conf.AMQPDefault)

	for c := range conf.AMQPSplitting {
		err = addAMQPConf(conf.AMQPSplitting[c])
		if err != nil {
			return err
		}
	}

	log.Println("Connected to AMQP")
	return nil
}

func main() {
	// Parse arguments
	var confPath string
	flag.StringVar(&confPath, "config", "", "Path to the config file")
	flag.Parse()
	if confPath == "" {
		confPath, _ = filepath.Abs(filepath.Dir(os.Args[0]))
		confPath = filepath.Join(confPath, "/config/gateway.conf")
	}

	// Read config
	conf = &config{MaxUploadSize: 200}
	cfile, _ := os.Open(confPath)
	err := json.NewDecoder(cfile).Decode(&conf)
	FailOnError(err, "Couldn't read config file")

	err = connectAMQP()
	FailOnError(err, "Failed while connecting to AMQP")
	initSourceRouting()
	initUsers()
	initHTTP()
}
