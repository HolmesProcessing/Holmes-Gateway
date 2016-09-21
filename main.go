package main

import (
	"flag"
	"github.com/HolmesProcessing/Holmes-Gateway/gateway"
	"github.com/HolmesProcessing/Holmes-Gateway/mastergateway"
	"os"
	"path/filepath"
)

func main() {
	var confPath string
	var master bool
	flag.StringVar(&confPath, "config", "", "Path to the config file")
	flag.BoolVar(&master, "master", false, "Start master gateway or organizational gateway")
	flag.Parse()

	if confPath == "" {
		confPath, _ = filepath.Abs(filepath.Dir(os.Args[0]))
		if master {
			confPath = filepath.Join(confPath, "/config/gateway-master.conf")
		} else {
			confPath = filepath.Join(confPath, "/config/gateway.conf")
		}
	}
	if master {
		mastergateway.Start(confPath)
	} else {
		gateway.Start(confPath)
	}

}
