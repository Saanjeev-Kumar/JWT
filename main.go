package main

import (
	"go-jwt-master/handler"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/signin", handler.Signin)
	http.HandleFunc("/welcome", handler.Welcome)
	http.HandleFunc("/refresh", handler.Refresh)
	http.HandleFunc("/logout", handler.Logout)

	// start server on port 8080
	log.Println("server started on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
