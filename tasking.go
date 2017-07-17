package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
)

var (
	srcRouter       map[string][]*Organization // Which source should be routed to which organization
	ownOrganization *Organization              // Pointer to the own organization in the list of organizations
)

type TaskError struct {
	TaskStruct TaskRequest
	Error      MyError
}

type GatewayAnswer struct {
	Error     *MyError
	TskErrors []TaskError
}

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

func requestTaskList(tasks []TaskRequest, org *Organization) (error, []byte) {
	req, err := http.NewRequest("GET", org.Uri+"/task_foreign/", nil)
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
	//TODO: Some form of ACL-checking...
	myerr, tskerrors := handleOwnTasks(tasks)
	answer := GatewayAnswer{
		Error:     myerr,
		TskErrors: tskerrors,
	}
	answer_json, _ := json.Marshal(answer)
	w.Write(answer_json)
	log.Println(string(answer_json))

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
