package main

import (
	"encoding/json"
	"net/http"
	"log"
	"os"
	"flag"
	"path/filepath"
	"github.com/julienschmidt/httprouter"
)

type config struct {
	HTTP string
}

type Task struct {
	User string
	SampleID string
	//TODO
}

func decrypt(encrypted string) (string) {
	decrypted := encrypted
	//TODO
	return decrypted
}

func validate(task string) (error, []Task) {
	var tasks []Task
	err := json.Unmarshal([]byte(task), &tasks)
	if err != nil {
		return err, nil
	}
	//TODO
	return err, tasks
}

func checkACL(task Task) (error){
	//TODO
	return nil
}

func httpRequestIncoming(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	tsk := ps.ByName("name")
	log.Println("httprequest..." + tsk);
	tsk = decrypt(tsk)
	err, tasks := validate(tsk)
	if err != nil {
		log.Println("Error while validating: ", err)
		return
	}
	for i := 0; i < len(tasks); i++ {
		err = checkACL(tasks[i])
		if err != nil {
			log.Println("Error while checking ACL: ", err)
			return
		}
	}
	log.Printf("%+v", tasks)
}

func initHTTP(httpBinding string) {
	router := httprouter.New()
	router.GET("/task/:name", httpRequestIncoming)
	log.Fatal(http.ListenAndServe(httpBinding, router))
}

func main() {
	var confPath string
	flag.StringVar(&confPath, "config", "", "Path to the config file")
	flag.Parse()

	if confPath == "" {
		confPath, _ = filepath.Abs(filepath.Dir(os.Args[0]))
		confPath += "/config.json"
	}

	conf := &config{}
	cfile, _ := os.Open(confPath)
	if err := json.NewDecoder(cfile).Decode(&conf); err != nil {
		log.Fatal("Couldn't read config file! ", err)
	}

	initHTTP(conf.HTTP)
}