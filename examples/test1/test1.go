package main

import (
	//"crypto/rand"
	//"encoding/base64"
	//"encoding/json"
	"errors"
	"flag"
	"fmt"
	//"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	//"sync"
	//"time"

	//oidc "github.com/coreos/go-oidc"

	"gopkg.in/yaml.v2"

	"golang.org/x/net/context"
	//"golang.org/x/oauth2"

	"git.symcpe.net/camilo_viecco1/go-simple-oidc-auth/authhandler"
)

var (
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

/*
type pendingConfig struct {
	ExpiresAt       time.Time
	Config          *oauth2.Config
	Provider        *oidc.Provider
	originalRequest *http.Request
	state           string
	ctx             *context.Context
}

type simpleUserInfo struct {
	ExpiresAt time.Time
	Sub       string
}

type SimpleOIDCAuth struct {
	ClientID     string
	ClientSecret string
	ProviderURL  string
	mutex        sync.Mutex
	oidcConfig   map[string]pendingConfig //map of cookievalue back to state
	authCookie   map[string]simpleUserInfo
	ctx          *context.Context
}

//const redirectPath = "/auth/google/callback"
const redirectPath = "/auth/oidcsimple/callback"
const redirCookieName = "oidc_redir_cookie"
const authCookieName = "oidc_auth_cookie"
const randomStringEntropyBytes = 32
const maxAgeSecondsRedirCookie = 300
const maxAgeSecondsAuthCookie = 3600

func writeFailureResponse(w http.ResponseWriter, code int, message string) {
	w.WriteHeader(code)
	publicErrorText := fmt.Sprintf("%d %s %s\n", code, http.StatusText(code), message)
	w.Write([]byte(publicErrorText))
}

func (state *SimpleOIDCAuth) getUserInfo(r *http.Request) (*simpleUserInfo, error) {
	cookie, err := r.Cookie(authCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			if *debug {
				log.Printf("no auth cookie present")
			}
			return nil, nil
		}
		return nil, err
	}
	index := cookie.Value
	state.mutex.Lock()
	info, ok := state.authCookie[index]
	state.mutex.Unlock()
	if !ok {
		log.Printf("Auth cookie not found")
		return nil, nil
	}
	// TODO ADD expiration check!
	log.Printf("Auth cookie found")

	return &info, nil
}

func genRandomString() (string, error) {
	size := randomStringEntropyBytes
	rb := make([]byte, size)
	_, err := rand.Read(rb)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(rb), nil

}

func (state *SimpleOIDCAuth) createRedirectionToProvider(w http.ResponseWriter, r *http.Request) {
	cookieVal, err := genRandomString()
	if err != nil {
		writeFailureResponse(w, http.StatusInternalServerError, "error internal")
		log.Println(err)
		return
	}

	// we have to create new context and set redirector...
	expiration := time.Now().Add(maxAgeSecondsRedirCookie * time.Second)
	//create localstate!

	provider, err := oidc.NewProvider(*state.ctx, state.ProviderURL)
	if err != nil {
		log.Fatal(err)
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	redirectUrl := scheme + "://" + r.Host + redirectPath

	config := oauth2.Config{
		ClientID:     state.ClientID,
		ClientSecret: state.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectUrl,
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}

	log.Printf("config : %+v", config)

	stateString, err := genRandomString()
	if err != nil {
		writeFailureResponse(w, http.StatusInternalServerError, "error internal")
		log.Println(err)
		return
	}

	cookie := http.Cookie{Name: redirCookieName, Value: cookieVal,
		Expires: expiration, Path: "/", HttpOnly: true}
	http.SetCookie(w, &cookie)

	pending := pendingConfig{ExpiresAt: expiration,
		Config:          &config,
		Provider:        provider,
		originalRequest: r, state: stateString, ctx: state.ctx}
	state.mutex.Lock()
	state.oidcConfig[cookieVal] = pending
	state.mutex.Unlock()

	http.Redirect(w, r, config.AuthCodeURL(stateString), http.StatusFound)
}

func (state *SimpleOIDCAuth) handleRedirectPath(w http.ResponseWriter, r *http.Request, h http.Handler) {
	redirCookie, err := r.Cookie(redirCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			writeFailureResponse(w, http.StatusBadRequest, "Missing setup cookie!")
			log.Println(err)
			return
		}
		writeFailureResponse(w, http.StatusInternalServerError, "error internal")
		log.Println(err)
		return
	}
	index := redirCookie.Value
	state.mutex.Lock()
	pending, ok := state.oidcConfig[index]
	state.mutex.Unlock()
	if !ok {
		// clear cookie here!!!!
		writeFailureResponse(w, http.StatusBadRequest, "Invalid setup cookie!")
		log.Println(err)
		return
	}

	if r.URL.Query().Get("state") != pending.state {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}
	log.Printf("req : %+v", r)
	oauth2Token, err := pending.Config.Exchange(*pending.ctx, r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("ctx: %+v", *pending.ctx)
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	userInfo, err := pending.Provider.UserInfo(*pending.ctx, oauth2.StaticTokenSource(oauth2Token))
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
	//w.Write(data)
	log.Printf("%+s", data)

	//set new auth cookie!
	cookieVal, err := genRandomString()
	if err != nil {
		writeFailureResponse(w, http.StatusInternalServerError, "error internal")
		log.Println(err)
		return
	}
	savedUserInfo := simpleUserInfo{Sub: "foo"}
	state.mutex.Lock()
	state.authCookie[cookieVal] = savedUserInfo
	state.mutex.Unlock()

	// we have to create new context and set redirector...
	//set the cookie and then redirect
	expiration := time.Now().Add(maxAgeSecondsAuthCookie * time.Second)

	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal, Expires: expiration, Path: "/", HttpOnly: true}

	//use handler with original request.
	http.SetCookie(w, &authCookie)

	http.Redirect(w, r, pending.originalRequest.URL.String(), http.StatusFound)
}

func (state *SimpleOIDCAuth) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *debug {
			log.Printf("Top os simple Auth target=%s\n", r.URL.String())
		}
		userInfo, err := state.getUserInfo(r)
		if err != nil {
			writeFailureResponse(w, http.StatusInternalServerError, "error internal")
			log.Println(err)
			return
		}
		if userInfo != nil {
			//found actual user... call original handler verbatim
			h.ServeHTTP(w, r)
			log.Println("After")
			return
		}
		if *debug {
			log.Printf("Dont have valid user... do openidc dance")
		}
		// We dont have a valid user...
		if r.URL.Path != redirectPath {
			if *debug {
				log.Printf("Doing redirection now")
			}
			state.createRedirectionToProvider(w, r)
			return
		}
		state.handleRedirectPath(w, r, h)

	})
}

func NewSimpleOIDCAuth(ctx *context.Context, clientID string, clientSecret string, providerURL string) *SimpleOIDCAuth {
	oidcAuthState := SimpleOIDCAuth{ClientID: clientID, ClientSecret: clientSecret, ProviderURL: providerURL, ctx: ctx}
	oidcAuthState.oidcConfig = make(map[string]pendingConfig)
	oidcAuthState.authCookie = make(map[string]simpleUserInfo)
	return &oidcAuthState
}
*/

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
}

func main() {
	flag.Parse()

	appConfig, err := loadVerifyConfigFile(*configFilename)
	if err != nil {
		panic(err)
	}
	log.Printf("appConfig: %+v\n", appConfig)
	//clientSecret = appConfig.Base.ClientSecret

	////
	ctx := context.Background()
	simpleOidcAuth := authhandler.NewSimpleOIDCAuth(&ctx, appConfig.Base.ClientID, appConfig.Base.ClientSecret, appConfig.Base.ProviderURL)

	//http.HandleFunc("/", handler)
	finalHandler := http.HandlerFunc(handler)
	//http.Handle("/", OidcAuthState.Handler(finalHandler))
	http.Handle("/", simpleOidcAuth.Handler(finalHandler))
	log.Printf("listening on http://%s/", "127.0.0.1:5556")
	log.Fatal(http.ListenAndServe("127.0.0.1:5556", nil))
}
