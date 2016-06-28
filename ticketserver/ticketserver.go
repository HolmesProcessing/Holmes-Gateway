package main

import (
	"log"
	"os"
	"flag"
	"time"
	"net/http"
	"crypto/rsa"
	"encoding/json"
	"path/filepath"
	"github.com/HolmesProcessing/Holmes-Gateway/utils"
)

type config struct {
	HTTP           string
	KeyPath        string
}


var conf *config
var key *rsa.PrivateKey

func createTicket() (tasking.Ticket){
	//TODO
	return tasking.Ticket {
		Expiration : time.Now().Add(3*time.Hour)}
}

func checkACL() (error){
	//TODO: How shall ACL-Check be executed?
	return nil
}

func httpRequestIncoming(w http.ResponseWriter, r *http.Request) {
	// TODO: Send an answer (fail/success)
	checkACL()
	t := createTicket()
	ts, err := json.Marshal(t)
	if err != nil {
		log.Println(err)
		
	} else {
		w.Write(ts)
	}
}

func initHTTP() {
	http.HandleFunc("/ticket/", httpRequestIncoming)
	log.Printf("Listening on %s\n", conf.HTTP)
	log.Fatal(http.ListenAndServe(conf.HTTP, nil))
}

func main() {
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
	tasking.FailOnError(err, "Couldn't read config file")
	
	// Parse the private keys
	key, _ = tasking.LoadPrivateKey(conf.KeyPath)

	// Setup the HTTP-listener
	initHTTP()
}
