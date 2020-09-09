// Program keyserver implements an HTTP server that generates
// keyfish passphrases in response to client requests.
package main

import (
	"flag"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/creachadair/keyfish/service"
)

var (
	port = flag.Int("port", 8080, "Service port")

	allowFrom = flag.String("allow", "",
		"CIDR blocks to allow connections from (CSV; empty to allow all)")
	configFile = flag.String("key-config", "",
		"Keyfish configuration file path")
)

func main() {
	flag.Parse()

	cfg := &service.Config{
		KeyConfigPath: *configFile,
		CheckAllow:    mustHostFilter(*allowFrom),
	}

	addr := "0.0.0.0:" + strconv.Itoa(*port)
	if err := http.ListenAndServe(addr, cfg); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}

func mustHostFilter(allow string) func(*http.Request) error {
	if allow == "" {
		return nil
	}
	filter, err := service.NewHostFilter(strings.Split(allow, ","))
	if err != nil {
		log.Fatalf("Invalid host filter: %v", err)
	}
	return filter.CheckAllow
}
