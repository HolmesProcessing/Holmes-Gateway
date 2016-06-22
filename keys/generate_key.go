package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"encoding/pem"
	"log"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("No filename specified!")
	}
	fname := os.Args[1]
	log.Println(fname)
	priv, err := rsa.GenerateKey(rand.Reader,1024)
	if err != nil {
		log.Fatal("Error generating key:", err)
	}

	pemdataPriv := pem.EncodeToMemory(
		&pem.Block{
			Type: "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)
	pub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		log.Fatal("Error generating key:", err)
	}

	pemdataPub := pem.EncodeToMemory(
		&pem.Block{
			Type: "RSA PUBLIC KEY",
			Bytes: pub,
		},
	)
	fPriv, err := os.Create("./"+fname+".priv")

	fPub, err := os.Create("./"+fname+".pub")
	_, err = fPriv.Write(pemdataPriv)
	_, err = fPub.Write(pemdataPub)
	log.Printf("%+v\n", priv)
	log.Println(priv)
	log.Println(string(pemdataPriv))
	log.Printf("%+v\n", priv.PublicKey)
	log.Println(pub)
	log.Println(string(pemdataPub))

}
