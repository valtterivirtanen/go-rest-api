package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq"
)

type Page struct {
	Title            string
	Heading1         string
	NotAuthenticated bool
}

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"-"`
}

var tpl *template.Template
var signuptpl *template.Template
var db *sql.DB

func init() {
	tpl = template.Must(template.ParseFiles("templates/tpl.gohtml"))
	signuptpl = template.Must(template.ParseFiles("templates/signup.gohtml"))
	err := error(nil)
	db, err = sql.Open("postgres", "postgres://depeoudeuwldzo:56fc88f2e91d47084a67c3c00286b88eb6a9093d75f31f63027aadafa49e535b@ec2-79-125-124-30.eu-west-1.compute.amazonaws.com:5432/db0busq5pa2aas")

	if err != nil {
		panic(err)
	}

	if err = db.Ping(); err != nil {
		panic(err)
	}
	fmt.Println("You connected to your database.")

}

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
	}

	http.HandleFunc("/", index)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/loggedIn", loggedIn)
	http.HandleFunc("/signUp", signUpHandler)
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css/"))))

	http.HandleFunc("/api/users", usersHandler)
	//http.HandleFunc("/api/users/{id}", singleUserHandler)
	/*
		err := http.ListenAndServe(":"+port, nil)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	*/

	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func index(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		home := Page{
			Title:            "My Login Page",
			Heading1:         "Project login-page",
			NotAuthenticated: true,
		}

		err := tpl.ExecuteTemplate(w, "tpl.gohtml", home)

		checkIfError(err)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func loggedIn(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		page := Page{
			Title:    "Logged In",
			Heading1: "Logged In Successfully",
		}

		err := tpl.ExecuteTemplate(w, "tpl.gohtml", page)

		checkIfError(err)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		r.ParseForm()
		name := r.FormValue("name")
		passwrd := r.FormValue("password")
		redirectTo := "/"

		if name != "" && passwrd != "" {
			redirectTo = "/loggedIn"
			err := validateCredentials(name, passwrd)
			if err == false {
				http.Error(w, "Invalid Credentials", http.StatusUnauthorized)
			}
		}

		http.Redirect(w, r, redirectTo, 302)
	}
}

func validateCredentials(name string, passwrd string) bool {

	hashedPwd, err := getHashedPassword(name, passwrd)

	if err != nil {
		log.Println(err)
		return false
	}

	err = validPassword(passwrd, hashedPwd)

	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

func validPassword(pwd string, hashPwd string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashPwd), []byte(pwd))

	return err
}

func signUpHandler(w http.ResponseWriter, r *http.Request) {

	page := Page{
		Title:    "Please Sign Up",
		Heading1: "Sign Up Please",
	}

	err := signuptpl.ExecuteTemplate(w, "signup.gohtml", page)

	checkIfError(err)
}

func checkIfError(e error) {
	if e != nil {
		log.Fatalln(e)
	}
}

func usersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		users, err := getUsers()

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		json.NewEncoder(w).Encode(users)

	case "POST":

		name := r.FormValue("name")
		email := r.FormValue("email")
		passwrd := hashPwd([]byte(r.FormValue("password")))

		userToBeCreated := User{-1, email, name, passwrd}

		user, err := createUser(&userToBeCreated)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		json.NewEncoder(w).Encode(user)
		http.Redirect(w, r, "/", http.StatusCreated)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func createUser(u *User) (*User, error) {
	_, err := db.Query("INSERT INTO users(username, email, password) VALUES ($1,$2,$3)", u.Username, u.Email, u.Password)

	if err != nil {
		return nil, err
	}

	user := User{}

	if err2 := db.QueryRow("SELECT id, email, username FROM users WHERE username=$1", u.Username).Scan(&user.ID, &user.Email, &user.Username); err2 != nil {
		return nil, err2
	}

	return &user, nil
}

func getUsers() ([]*User, error) {
	rows, err := db.Query("SELECT id, email, username FROM users")

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	users := []*User{}

	for rows.Next() {
		user := User{}

		if err := rows.Scan(&user.ID, &user.Email, &user.Username); err != nil {
			return nil, err
		}
		users = append(users, &user)
	}

	return users, nil

}

func getHashedPassword(username string, password string) (string, error) {
	var hashedPassword string

	if err := db.QueryRow("SELECT password FROM users WHERE username=$1", username).Scan(&hashedPassword); err != nil {
		return "", err
	}

	return hashedPassword, nil
}

func hashPwd(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, 10)

	checkIfError(err)

	return string(hash)
}
