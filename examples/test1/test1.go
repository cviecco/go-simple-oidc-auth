package main

import (
	"encoding/json"
	"errors"
	"flag"
	//"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	oidc "github.com/coreos/go-oidc"

	"gopkg.in/yaml.v2"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

var (
	clientID       = os.Getenv("GOOGLE_OAUTH2_CLIENT_ID")
	clientSecret   = os.Getenv("GOOGLE_OAUTH2_CLIENT_SECRET")
	configFilename = flag.String("config", "config.yml", "The filename of the configuration")
	debug          = flag.Bool("debug", true, "Enable debug messages to console")
)

type baseConfig struct {
	ClientID     string
	ClientSecret string
	ProviderURL  string
}

type AppConfigFile struct {
	Base baseConfig
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

func main() {
	flag.Parse()

	appConfig, err := loadVerifyConfigFile(*configFilename)
	if err != nil {
		panic(err)
	}
	log.Printf("appConfig: %+v\n", appConfig)
	clientID = appConfig.Base.ClientID
	clientSecret = appConfig.Base.ClientSecret

	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, appConfig.Base.ProviderURL)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("prov:%+v", provider)
	config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://127.0.0.1:5556/auth/google/callback",
		//Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		Scopes: []string{oidc.ScopeOpenID, "profile"},
	}

	log.Printf("config : %+v", config)
	state := "foobar" // Don't do this in production.

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, config.AuthCodeURL(state), http.StatusFound)
	})

	http.HandleFunc("/auth/google/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state did not match", http.StatusBadRequest)
			return
		}
		log.Printf("req : %+v", r)
		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			log.Printf("ctx: %+v", ctx)
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			http.Error(w, "Failed to get userinfo: "+err.Error(), http.StatusInternalServerError)
			return
		}

		resp := struct {
			OAuth2Token *oauth2.Token
			UserInfo    *oidc.UserInfo
		}{oauth2Token, userInfo}
		data, err := json.MarshalIndent(resp, "", "    ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	log.Printf("listening on http://%s/", "127.0.0.1:5556")
	log.Fatal(http.ListenAndServe("127.0.0.1:5556", nil))
}
