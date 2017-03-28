package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/cviecco/go-simple-oidc-auth/authhandler"
)

func handler(w http.ResponseWriter, r *http.Request) {
	userInfo, err := authhandler.GetRemoteUserInfo(r)
	if err != nil {
		panic(err)
	}
	if userInfo == nil {
		panic("null userinfo!")
	}
	fmt.Fprintf(w, "Hi there, %s loves %s!", *userInfo.Username, r.URL.Path[1:])
}

func main() {
	// The original code was just:
	// http.HandleFunc("/", handler)
	authhandler.HandleFunc("/", handler)

	log.Printf("listening on http://%s/", "127.0.0.1:5556")
	log.Fatal(http.ListenAndServe("127.0.0.1:5556", nil))
}
