package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/cviecco/go-simple-oidc-auth/authhandler"
)

var (
	configFilename = flag.String("config", "config.yml", "The filename of the configuration")
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
}

func main() {
	flag.Parse()

	// if you alresy use the context:
	//ctx := context.Background()
	// simpleOidcAuth, err := authhandler.NewSimpleOIDCAuthFromConfig(configFilename, &ctx)
	simpleOidcAuth, err := authhandler.NewSimpleOIDCAuthFromConfig(configFilename, nil)
	if err != nil {
		panic(err)
	}

	// The original code was just:
	// http.HandleFunc("/", handler)
	// Now we first make it into a handler and use this as
	//finalHandler := http.HandlerFunc(handler)
	http.Handle("/", simpleOidcAuth.Handler(http.HandlerFunc(handler)))

	log.Printf("listening on http://%s/", "127.0.0.1:5556")
	log.Fatal(http.ListenAndServe("127.0.0.1:5556", nil))
}
