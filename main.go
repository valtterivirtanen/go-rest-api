package main

import (
	"encoding/json"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"

	"github.com/gorilla/mux"
)

const secret = "tÃ¤tÃ¤.ei_kukaan|tosta,v44nvoiarvata?EIHÃ„N!?"

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
		log.Printf("Port defaulted to %v\n", port)
	}
	rtr := mux.NewRouter()

	rtr.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		in = make(map[string]string)
		in["server"] = "running"
		json.NewEncoder(w).Encode(in)

	}).Methods("GET", "OPTIONS")
	rtr.Handle("/get-token", errorCatcher(getToken)).Methods("POST")

	apiRouter := rtr.PathPrefix("/api").Subrouter()

	apiRouter.Handle("/users", errorCatcher(getUsers)).Methods("GET")
	apiRouter.Handle("/users", errorCatcher(createUser)).Methods("POST")
	apiRouter.Handle("/users/{id:[0-9]+}", errorCatcher(getUser)).Methods("GET")
	apiRouter.Handle("/users/{id:[0-9]+}", errorCatcher(updateUser)).Methods("PUT")
	apiRouter.Handle("/users/{id:[0-9]+}", errorCatcher(deleteUser)).Methods("DELETE")

	rtr.NotFoundHandler = http.Handler(applyHeadersMiddleware(errorCatcher(my404Handler)))
	rtr.MethodNotAllowedHandler = http.Handler(applyHeadersMiddleware(errorCatcher(my405Handler)))

	rtr.Use(myLoggerMiddleware, applyHeadersMiddleware, checkContentTypeMiddleware)
	apiRouter.Use(authenticationMiddleware)

	log.Fatal(http.ListenAndServe(":"+port, rtr))
}

func applyHeadersMiddleware(next http.Handler) http.Handler {
	return http.Handler(errorCatcher(func(w http.ResponseWriter, r *http.Request) *MyError {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")

		next.ServeHTTP(w, r)

		return nil
	}))
}

func checkContentTypeMiddleware(next http.Handler) http.Handler {
	return http.Handler(errorCatcher(func(w http.ResponseWriter, r *http.Request) *MyError {
		ct := r.Header.Get("Content-Type")
		if m, _, err := mime.ParseMediaType(ct); m != "application/json" || err != nil {
			return &MyError{&MyErrorProps{"not acceptable content-type", err, 406, ""}}
		}
		next.ServeHTTP(w, r)

		return nil
	}))
}

func myLoggerMiddleware(next http.Handler) http.Handler {
	return http.Handler(errorCatcher(func(w http.ResponseWriter, r *http.Request) *MyError {
		ip := r.RemoteAddr
		forward := r.Header.Get("X-Forwarded-For")
		if len(forward) == 0 {
			forward = "-"
		}
		start := time.Now()

		ua := r.Header.Get("User-Agent")
		mthd := r.Method
		url := r.RequestURI
		proto := r.Proto

		next.ServeHTTP(w, r)

		duration := time.Now().Sub(start)

		text := fmt.Sprintf("%s\t(%s)\t%s\t\"%s\t%s\t%s\"\t%s\t%s\n", ip, forward, start.Format(time.RFC3339), mthd, url, proto, ua, duration)

		f, err := os.OpenFile("requests.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return &MyError{&MyErrorProps{"opening log file failed", err, 400, ""}}
		}

		defer f.Close()

		if _, err = f.WriteString(text); err != nil {
			return &MyError{&MyErrorProps{"writing log file failed", err, 400, ""}}

		}

		return nil
	}))
}
