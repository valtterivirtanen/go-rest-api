package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
)

type MyError struct {
	Err *MyErrorProps `json:"error"`
}

type MyErrorProps struct {
	Message    string `json:"message"`
	Error      error  `json:"-"`
	StatusCode int    `json:"code"`
	StatusText string `json:"status"`
}

type errorCatcher func(http.ResponseWriter, *http.Request) *MyError

func (fn errorCatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e := fn(w, r); e != nil {

		log.Printf("Error: %v\n", e.Err.Error)
		w.WriteHeader(e.Err.StatusCode)
		e.Err.StatusText = http.StatusText(e.Err.StatusCode)
		json.NewEncoder(w).Encode(e)
	}
}

func my404Handler(w http.ResponseWriter, r *http.Request) *MyError {
	return &MyError{&MyErrorProps{"resource not found", errors.New("page not found: " + r.URL.String()), 404, ""}}
}

func my405Handler(w http.ResponseWriter, r *http.Request) *MyError {
	mna := fmt.Sprintf("method not allowed: %v", r.Method)
	return &MyError{&MyErrorProps{mna, errors.New(mna), 405, ""}}
}
