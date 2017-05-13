package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
)

type User struct {
	Name         string `json:"name"`
	Id           int    `json:"id"`
	PasswordHash string `json:"pw"`
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

	DisableStorageVerify bool

	AMQP          string
	AMQPDefault   AMQPConf
	AMQPSplitting map[string]AMQPConf
}

var (
	conf                  *config          // The configuration struct
	storageURIStoreSample url.URL          // The URL to storage for redirecting object-storage requests
	users                 map[string]*User // Map: Username -> User-struct (TODO: Move to storage)
)

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
	uri, _ := url.Parse(conf.StorageSampleURI + "store")
	storageURIStoreSample = *uri
	proxy = httputil.NewSingleHostReverseProxy(uri)
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
		log.Printf("User '%s' does not exist", username)
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
	conf = &config{MaxUploadSize: 200, DisableStorageVerify: false}
	cfile, _ := os.Open(confPath)
	err := json.NewDecoder(cfile).Decode(&conf)
	FailOnError(err, "Couldn't read config file")

	err = connectAMQP()
	FailOnError(err, "Failed while connecting to AMQP")
	initSourceRouting()
	initUsers()
	initHTTP()
}
