package main

import (
	"encoding/json"
	"net/http"
	"log"
	"os"
	"flag"
	"errors"
	//"crypto/aes"
	//"crypto/cipher"
	"path/filepath"
	"github.com/julienschmidt/httprouter"
)

type config struct {
	HTTP string
}

// Tasks are encrypted with a symmetric key (EncryptedKey), which is
// encrypted with the asymmetric key in KeyFingerprint
type EncryptedTask struct {
	KeyFingerprint  string `json:"asymkey"`
	EncryptedKey    []byte `json:"symkey"`
	Encrypted       []byte
}

type Task struct {
	User     string
	SampleID string
	//TODO
}

func aesDecrypt(text []byte, key []byte) (error, []byte) {
	//TODO
	return nil, text
}

func rsaDecrypt(text []byte, key []byte) (error, []byte) {
	//TODO
	return nil, text
}

func decrypt(encrypted string) (error, string) {
	var enc []EncryptedTask
	if err := json.Unmarshal([]byte(encrypted), &enc); err != nil {
		return err, ""
	} else if len(enc) != 1 {
		return errors.New("Only one encrypted task per request!"), ""
	}
	log.Printf("Parsed: %+v\n", enc)
	//TODO: Fetch private key corresponding to enc[0].keyFingerprint (from where?)
	asymKey := []byte(enc[0].KeyFingerprint)
	
	//TODO: Actually implement decryption-function!
	//      For now: dec(a) = a
	// Decrypt symmetric key using the asymmetric key
	err, symKey := rsaDecrypt(enc[0].EncryptedKey, asymKey)
	if err != nil{
		return err, ""
	}

	//TODO: Actually implement decryption-function!
	//      For now: dec(a) = a
	// Decrypt using the symmetric key
	err, decrypted := aesDecrypt(enc[0].Encrypted, symKey)
	return err, string(decrypted)
}

func validate(task string) (error, []Task) {
	var tasks []Task
	err := json.Unmarshal([]byte(task), &tasks)
	if err != nil {
		return err, nil
	}
	//TODO Check for required fields; Additional checks?
	return err, tasks
}

func checkACL(task Task) (error){
	//TODO: How shall ACL-Check be executed?
	return nil
}

func httpRequestIncoming(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	task := ps.ByName("name")[1:]
	log.Println("New task request:\n" + task);
	err, decTask := decrypt(task)
	if err != nil {
		log.Println("Error while decrypting: ", err)
		return
	}
	log.Println("Decrypted task:", decTask)
	err, tasks := validate(decTask)
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
	router.GET("/task/*name", httpRequestIncoming)
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