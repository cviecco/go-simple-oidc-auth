package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"gopkg.in/yaml.v2"

	"golang.org/x/net/context"

	"git.symcpe.net/camilo_viecco1/go-simple-oidc-auth/authhandler"
)

var (
	configFilename = flag.String("config", "config.yml", "The filename of the configuration")
	debug          = flag.Bool("debug", true, "Enable debug messages to console")
)

type OidcConfig struct {
	ClientID     string
	ClientSecret string
	ProviderURL  string
}

type AppConfigFile struct {
	Openidc OidcConfig
}

func loadVerifyConfigFile(configFilename string) (AppConfigFile, error) {
	var config AppConfigFile
	if _, err := os.Stat(configFilename); os.IsNotExist(err) {
		err = errors.New("mising config file failure")
		return config, err
	}
	source, err := ioutil.ReadFile(configFilename)
	if err != nil {
		//panic(err)
		err = errors.New("cannot read config file")
		return config, err
	}
	err = yaml.Unmarshal(source, &config)
	if err != nil {
		err = errors.New("Cannot parse config file")
		return config, err
	}
	return config, nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
}

func main() {
	flag.Parse()

	config, err := loadVerifyConfigFile(*configFilename)
	if err != nil {
		panic(err)
	}
	log.Printf("appConfig: %+v\n", config)

	////
	ctx := context.Background()
	simpleOidcAuth := authhandler.NewSimpleOIDCAuth(&ctx, config.Openidc.ClientID, config.Openidc.ClientSecret, config.Openidc.ProviderURL)

	//http.HandleFunc("/", handler)
	finalHandler := http.HandlerFunc(handler)
	//http.Handle("/", OidcAuthState.Handler(finalHandler))
	http.Handle("/", simpleOidcAuth.Handler(finalHandler))
	log.Printf("listening on http://%s/", "127.0.0.1:5556")
	log.Fatal(http.ListenAndServe("127.0.0.1:5556", nil))
}
