package main

import (
	"html/template"
	"log"
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
	home := Page{
		Title:    "My Login Page",
		Heading1: "Project login-page",
		Content:  "<p>Grrrrrr</p>",
	}

	err := tpl.ExecuteTemplate(os.Stdout, "tpl.gohtml", home)

	if err != nil {
		log.Fatalln(err)
	}
}
