package main

import (
	"html/template"
	"log"
	"net/http"
	"os"
)

type Page struct {
	Title    string
	Heading1 string
	Content  string
}

var tpl *template.Template

func init() {
	tpl = template.Must(template.ParseFiles("tpl.gohtml"))
}

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
	}

	http.HandleFunc("/", index)

	http.ListenAndServe(":"+port, nil)
}

func index(w http.ResponseWriter, r *http.Request) {
	home := Page{
		Title:    "My Login Page",
		Heading1: "Project login-page",
		Content:  "<p>Grrrrrr</p>",
	}

	err := tpl.ExecuteTemplate(w, "tpl.gohtml", home)

	if err != nil {
		log.Fatalln(err)
	}
}
