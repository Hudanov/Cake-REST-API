package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
)

var wsPort = os.Getenv("WEBSOCKET_PORT")
var addr = flag.String("addr", ":"+wsPort, "http service address")

func main() {
	flag.Parse()
	hub := NewHub()
	go hub.run()
	go hub.receive()

	jwtService, err := NewJWTService()
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if _, err := jwtService.ParseJWT(token); err != nil {
			w.WriteHeader(401)
			w.Write([]byte("unauthorized"))
			return
		}

		serveWS(hub, w, r)
	})

	err = http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
