package main

import (
	"testing"
	"encoding/base64"
	)

func TestValidateTask(t *testing.T) {
	task := "[{\"User\":\"u1\", \"SampleID\":\"s1\"}]"
	v, err := validateTask(task)
	if err != nil {
		t.Error(err)
	} else if ((v[0].User != "u1") || (v[0].SampleID != "s1")) {
		t.Error("User should be 'u1' and SampleID should be 's1'", v)
	}
}

func TestAESDecrypt(t *testing.T) {
	ciphertext, err := base64.StdEncoding.DecodeString("H6bNAXHIFpgqeJ2Kd+SJOg==")
	if err != nil {
		t.Error(err)
	}
	v, err := aesDecrypt(ciphertext, []byte("abcdef0123456789"), []byte("0000111122223333"))
	if err != nil {
		t.Error(err)
	} else if (string(v) != ("test encryption!")) {
		t.Error("Should be 'test encryption!' ", string(v))
	}
}