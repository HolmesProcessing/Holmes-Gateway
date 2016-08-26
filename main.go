package main
import (
	"os"
	"flag"
	"path/filepath"
	"./mastergateway"
	"./gateway"
)

func main() {
	var confPath string
	var master bool
	flag.StringVar(&confPath, "config", "", "Path to the config file")
	flag.BoolVar(&master, "master", false, "Start master gateway or organizational gateway")
	flag.Parse()

	if confPath == "" {
		confPath, _ = filepath.Abs(filepath.Dir(os.Args[0]))
		confPath += "/config/gateway.conf"
	}
	if master {
		mastergateway.Start(confPath)
	} else {
		gateway.Start(confPath)
	}

}
