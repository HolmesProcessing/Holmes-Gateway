package gateway

import (
	"testing"
	"encoding/base64"
	"log"
	"encoding/json"
	"github.com/HolmesProcessing/Holmes-Gateway/utils"
	)

func TestRSA(t *testing.T) {
	print("RSA-Test\n")
	rsakey,_ := loadPrivateKey("keys/blub.priv")
	p1 := "abcdef0123456789"
	c, err := tasking.RsaEncrypt([]byte(p1), &rsakey.PublicKey)
	if err != nil {
		t.Error(err)
	}
	print(base64.StdEncoding.EncodeToString(c)+"\n")
	p2, err := tasking.RsaDecrypt(c, rsakey)
	if err != nil {
		t.Error(err)
	} else if (p1 != string(p2)) {
		t.Error("should be '", p1, "' is '", string(p2), "'")
	}
}

func TestValidateTask(t *testing.T) {
	ta := tasking.Task{
		PrimaryURI : "http://127.0.0.1:8016/samples/3a12f43eeb0c45d241a8f447d4661d9746d6ea35990953334f5ec675f60e36c5",
		SecondaryURI : "",
		Filename : "myfile",
		Tasks: map[string][]string{"PEINFO": []string{""}, "YARA": []string{""}},
		Tags : []string{"test1"},
		Attempts : 0 }

	task, err := json.Marshal([]tasking.Task{ta})
	if err != nil {
		t.Error(err)
	}
	v, err := validateTask(string(task))
	if err != nil {
		t.Error(err)
	} else if ((v[0].PrimaryURI != ta.PrimaryURI) || (v[0].SecondaryURI != ta.SecondaryURI)) {
		t.Error("Error: ", v)
	}
}

func TestAESDecrypt(t *testing.T) {
	ciphertext, err := base64.StdEncoding.DecodeString("H6bNAXHIFpgqeJ2Kd+SJOnBjz94QSGAy+OeP096SZDM=")

	if err != nil {
		t.Error(err)
	}

	v, err := tasking.AesDecrypt(ciphertext, []byte("abcdef0123456789"), []byte("0000111122223333"))
	if err != nil {
		t.Error(err)
	} else if (string(v) != ("test encryption!")) {
		t.Error("Should be 'test encryption!' ", string(v), v)
	}
}

func TestAES(t *testing.T) {
	print("AES-Test\n")
	ta := tasking.Task{
		PrimaryURI : "http://127.0.0.1:8016/samples/3a12f43eeb0c45d241a8f447d4661d9746d6ea35990953334f5ec675f60e36c5",
		SecondaryURI : "",
		Filename : "myfile",
		Tasks: map[string][]string{"PEINFO": []string{""}, "YARA": []string{""}},
		Tags : []string{"test1"},
		Attempts : 5 }

	task, err := json.Marshal([]tasking.Task{ta})
	if err != nil {
		t.Error(err)
	}

	plaintext := []byte(task)
	log.Printf(string(plaintext))
	key := []byte("abcdef0123456789")
	iv := []byte("0000111122223333")

	ciphertext, err := tasking.AesEncrypt(plaintext, key, iv)

	if err != nil {
		t.Error(err)
	}
	print(base64.StdEncoding.EncodeToString(ciphertext)+"\n")

	plaintext2, err := tasking.AesDecrypt(ciphertext, key, iv)
	if err != nil {
		t.Error(err)
	} else if (string(plaintext2) != string(plaintext)) {
		t.Error("Should be", len(string(plaintext)), len(string(plaintext2)), "\n", plaintext,"\n", plaintext2)
	}
}
