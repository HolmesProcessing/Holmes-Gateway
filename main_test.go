package main

import (
	"testing"
	"encoding/base64"
	"log"
	"encoding/json"
	)

func TestRSA(t *testing.T) {
	print("RSA-Test\n")
	rsakey,_ := loadKey("keys/blub.priv")
	p1 := "abcdef0123456789"
	c, err := rsaEncrypt([]byte(p1), &rsakey)
	if err != nil {
		t.Error(err)
	}
	print(base64.StdEncoding.EncodeToString(c)+"\n")
	p2, err := rsaDecrypt(c, &rsakey)
	if err != nil {
		t.Error(err)
	} else if (p1 != string(p2)) {
		t.Error("should be '", p1, "' is '", string(p2), "'")
	}
}

func TestValidateTask(t *testing.T) {
	PrimaryURI := "www.samples.com"
	SecondaryURI := "www.samples2.com"
	task := "[{\"primaryURI\":\""+PrimaryURI+"\", \"secondaryURI\":\""+SecondaryURI+"\", \"attempts\": 10}]"
	v, err := validateTask(task)
	if err != nil {
		t.Error(err)
	} else if ((v[0].PrimaryURI != PrimaryURI) || (v[0].SecondaryURI != SecondaryURI)) {
		t.Error("Error: ", v)
	}
}

func TestAESDecrypt(t *testing.T) {
	ciphertext, err := base64.StdEncoding.DecodeString("H6bNAXHIFpgqeJ2Kd+SJOnBjz94QSGAy+OeP096SZDM=")

	if err != nil {
		t.Error(err)
	}
	
	v, err := aesDecrypt(ciphertext, []byte("abcdef0123456789"), []byte("0000111122223333"))
	if err != nil {
		t.Error(err)
	} else if (string(v) != ("test encryption!")) {
		t.Error("Should be 'test encryption!' ", string(v), v)
	}
}

func TestAES(t *testing.T) {
	print("AES-Test\n")
	ta := Task{
		PrimaryURI : "www.samples1.com/abcd",
		SecondaryURI : "www.samples2.com/efgh",
		Filename : "myfile",
		Tasks: map[string][]string{"PEINFO": []string{""}, "YARA": []string{""}},
		Tags : []string{"test1"},
		Attempts : 5 }

	task, err := json.Marshal([]Task{ta})
	if err != nil {
		t.Error(err)
	}

	plaintext := []byte(task)
	log.Printf(string(plaintext))
	key := []byte("abcdef0123456789")
	iv := []byte("0000111122223333")
	
	ciphertext, err := aesEncrypt(plaintext, key, iv)
	
	if err != nil {
		t.Error(err)
	}
	print(base64.StdEncoding.EncodeToString(ciphertext)+"\n")

	plaintext2, err := aesDecrypt(ciphertext, key, iv)
	if err != nil {
		t.Error(err)
	} else if (string(plaintext2) != string(plaintext)) {
		t.Error("Should be", len(string(plaintext)), len(string(plaintext2)), "\n", plaintext,"\n", plaintext2)
	}
}
