package authhandler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	oidc "github.com/coreos/go-oidc"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
)

const redirectPath = "/auth/oidcsimple/callback"
const redirCookieName = "oidc_redir_cookie"
const authCookieName = "oidc_auth_cookie"
const randomStringEntropyBytes = 32

var defaultOIDCAuth *SimpleOIDCAuth
var defaultContext context.Context
var maxAgeSecondsRedirCookie = 300
var maxAgeSecondsAuthCookie = 3600
var secsBetweenCleanup = 60

var DefaultConfigFilename = "/etc/openidc_config.yml"
var Debug = false

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

type UserInfo struct {
	Id       string
	Username *string
	Domain   *string
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

func writeFailureResponse(w http.ResponseWriter, code int, message string) {
	w.WriteHeader(code)
	publicErrorText := fmt.Sprintf("%d %s %s\n", code, http.StatusText(code), message)
	w.Write([]byte(publicErrorText))
}

func (state *SimpleOIDCAuth) getUserInfo(r *http.Request) (*simpleUserInfo, error) {
	cookie, err := r.Cookie(authCookieName)
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, nil
		}
		return nil, err
	}
	index := cookie.Value
	state.mutex.Lock()
	info, ok := state.authCookie[index]
	state.mutex.Unlock()
	if !ok {
		if Debug {
			log.Printf("Auth cookie not found")
		}
		return nil, nil
	}
	if Debug {
		log.Printf("Auth cookie found")
	}
	if info.ExpiresAt.Before(time.Now()) {
		return nil, nil
	}
	if Debug {
		log.Printf("Valid Auth cookie found")
	}

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
	expiration := time.Now().Add(time.Duration(maxAgeSecondsRedirCookie) * time.Second)

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
	if Debug {
		log.Printf("config : %+v", config)
	}

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

func (state *SimpleOIDCAuth) handleRedirectPath(w http.ResponseWriter, r *http.Request) {
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
	if Debug {
		log.Printf("req : %+v", r)
	}
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
	if Debug {
		log.Printf("%+s", data)
	}

	//set new auth cookie!
	cookieVal, err := genRandomString()
	if err != nil {
		writeFailureResponse(w, http.StatusInternalServerError, "error internal")
		log.Println(err)
		return
	}
	expiration := time.Now().Add(time.Duration(maxAgeSecondsAuthCookie) * time.Second)
	savedUserInfo := simpleUserInfo{Sub: resp.UserInfo.Subject, ExpiresAt: expiration}
	state.mutex.Lock()
	state.authCookie[cookieVal] = savedUserInfo
	state.mutex.Unlock()

	// we have to create new context and set redirector...
	//set the cookie and then redirect
	authCookie := http.Cookie{Name: authCookieName, Value: cookieVal, Expires: expiration, Path: "/", HttpOnly: true}

	//use handler with original request.
	http.SetCookie(w, &authCookie)

	// TODO: ask the browser to cleaup up the cookie.... will let the the reaper clean it up
	// from our local state...

	http.Redirect(w, r, pending.originalRequest.URL.String(), http.StatusFound)
}

func (state *SimpleOIDCAuth) isInitializedCorrectly() bool {
	if (state.ProviderURL == "") ||
		(state.ClientID == "") {
		return false
	}
	return true
}

func (state *SimpleOIDCAuth) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//if *debug {
		//	log.Printf("Top os simple Auth target=%s\n", r.URL.String())
		//}
		if !state.isInitializedCorrectly() {
			writeFailureResponse(w, http.StatusInternalServerError, "Auth system not initialized correctly")
			log.Println("state is NOT initialized")
			return
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
			//log.Println("After")
			return
		}
		//if *debug {
		//	log.Printf("Dont have valid user... do openidc dance")
		//}
		// We dont have a valid user...
		if r.URL.Path != redirectPath {
			//if *debug {
			//	log.Printf("Doing redirection now")
			//}
			state.createRedirectionToProvider(w, r)
			return
		}
		state.handleRedirectPath(w, r)

	})
}

func (state *SimpleOIDCAuth) cleanupOldState() {
	for {
		start := time.Now()
		state.mutex.Lock()
		initAuthSize := len(state.authCookie)
		for key, userInfo := range state.authCookie {
			if userInfo.ExpiresAt.Before(start) {
				delete(state.authCookie, key)
			}
		}
		finalAuthSize := len(state.authCookie)

		initPendingSize := len(state.oidcConfig)
		for key, pending := range state.oidcConfig {
			if pending.ExpiresAt.Before(start) {
				delete(state.oidcConfig, key)
			}
		}
		finalPendingSize := len(state.oidcConfig)
		state.mutex.Unlock()

		if Debug {
			log.Printf("Auth Cookie sizes: before:(%d) after (%d)\n", initAuthSize, finalAuthSize)
			log.Printf("Pending Cookie sizes: before:(%d) after (%d)\n", initPendingSize, finalPendingSize)
		}

		time.Sleep(time.Duration(secsBetweenCleanup) * time.Second)
	}
}

// Returns the remote username associated with the request or empty string if
// The user is not found
func (state *SimpleOIDCAuth) GetRemoteUserInfo(r *http.Request) (*UserInfo, error) {
	userInfo, err := state.getUserInfo(r)
	if err != nil {
		return nil, err
	}
	if userInfo == nil {
		return nil, nil
	}
	outUserInfo := UserInfo{Id: userInfo.Sub}

	sliced := strings.Split(userInfo.Sub, "@")
	outUserInfo.Username = &sliced[0]
	if len(sliced) > 1 {
		outUserInfo.Domain = &sliced[1]
	}
	return &outUserInfo, nil

}

func (state *SimpleOIDCAuth) Handle(pattern string, handler http.Handler) {
	http.Handle(pattern, state.Handler(handler))
}

func (state *SimpleOIDCAuth) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	http.Handle(pattern, state.Handler(http.HandlerFunc(handler)))
}

func NewSimpleOIDCAuth(ctx *context.Context, clientID string, clientSecret string, providerURL string) *SimpleOIDCAuth {
	oidcAuthState := SimpleOIDCAuth{ClientID: clientID, ClientSecret: clientSecret, ProviderURL: providerURL, ctx: ctx}
	oidcAuthState.oidcConfig = make(map[string]pendingConfig)
	oidcAuthState.authCookie = make(map[string]simpleUserInfo)
	go oidcAuthState.cleanupOldState()
	return &oidcAuthState
}

func initDefault() {
	defaultContext := context.Background()
	config, err := loadVerifyConfigFile(DefaultConfigFilename)
	if err != nil {
		log.Printf("unknown or invalid default config... using the default oath will result in errors %s", err)
	}
	defaultOIDCAuth = NewSimpleOIDCAuth(&defaultContext, config.Openidc.ClientID, config.Openidc.ClientSecret, config.Openidc.ProviderURL)
	http.HandleFunc(redirectPath, defaultOIDCAuth.handleRedirectPath)
}

func Handle(pattern string, handler http.Handler) {
	if defaultOIDCAuth == nil {
		initDefault()
	}

	defaultOIDCAuth.Handle(pattern, handler)
}

func HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	if defaultOIDCAuth == nil {
		initDefault()
	}
	defaultOIDCAuth.HandleFunc(pattern, handler)
}

func GetRemoteUserInfo(r *http.Request) (*UserInfo, error) {
	if defaultOIDCAuth == nil {
		initDefault()
	}
	return defaultOIDCAuth.GetRemoteUserInfo(r)
}
