package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path"
	"time"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq"

	//"github.com/gorilla/mux"
	"github.com/dgrijalva/jwt-go"
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

type MyError struct {
	Message string
	Path    string
	Error   error
	Code    int
}

type JWTToken struct {
	Token string `json:"token"`
}

type CustomClaims struct {
	jwt.StandardClaims
}

const secret = "tätä.ei_kukaan|tosta,v44nvoiarvata?EIHÄN!?"

var tpl *template.Template
var signuptpl *template.Template
var db *sql.DB

func init() {
	tpl = template.Must(template.ParseFiles("templates/tpl.gohtml"))
	signuptpl = template.Must(template.ParseFiles("templates/signup.gohtml"))
	err := error(nil)
	db, err = sql.Open("postgres", os.Getenv("DATABASE_URL"))

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
	//rtr := mux.NewRouter()

	http.HandleFunc("/", index)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/loggedIn", loggedIn)
	http.HandleFunc("/signUp", signUpHandler)
	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("css/"))))

	http.HandleFunc("/api/users", usersHandler)
	http.HandleFunc(`/api/users/1`, singleUserHandler)
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

		name := r.FormValue("name")
		passwrd := r.FormValue("password")
		redirectTo := "/"

		if name != "" && passwrd != "" {

			err := validateCredentials(name, passwrd)
			if err == true {
				//createToken(name)
				redirectTo = "/loggedIn"
			}
		}

		http.Redirect(w, r, redirectTo, 302)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func createToken(username string) *JWTToken {
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := make(jwt.MapClaims)
	claims["name"] = username
	claims["exp"] = time.Now().Add(time.Minute * 10).Unix()
	claims["admin"] = true

	tokenStr, _ := token.SignedString([]byte(secret))
	JWTToken := JWTToken{tokenStr}

	return &JWTToken
}

func singleUserHandler(w http.ResponseWriter, r *http.Request) {
	user := User{}

	switch r.Method {
	case "PUT":
		id := path.Base(r.URL.Path)

		err := db.QueryRow("SELECT id, email, username FROM users WHERE id=$1", id).Scan(&user.ID, &user.Email, &user.Username)

		v := r.FormValue("username")
		if len(v) > 0 {
			user.Username = v
		}

		v = r.FormValue("email")
		if len(v) > 0 {
			user.Email = v
		}

		if err != nil {
			log.Println(err)
		} else {
			_, err = db.Exec("UPDATE users SET email=$1, username=$2 WHERE id=$3", user.Email, user.Username, user.ID)
		}

		if err != nil {
			log.Println(err)
		}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")

		json.NewEncoder(w).Encode(user)
	case "GET":
		params := r.URL.Query()
		id := params.Get("id")
		//id := path.Base(r.URL.Path)
		fmt.Println(params)
		fmt.Println(r.URL.Query())
		fmt.Println(r.URL.Path)
		if len(id) == 0 {
			http.Error(w, "User not found", http.StatusNotFound)
		}
		if err := db.QueryRow("SELECT id, email, username FROM users WHERE id=$1", id).Scan(&user.ID, &user.Email, &user.Username); err != nil {
			log.Println(err)
		}

		w.Header().Set("Content-Type", "application/json; charset=UTF-8")

		json.NewEncoder(w).Encode(user)
	case "DELETE":
		id := path.Base(r.URL.Path)

		err := db.QueryRow("DELETE FROM users WHERE id=$1 RETURNING id,username,email", id).Scan(&user.ID, &user.Email, &user.Username)

		if err != nil {
			log.Println(err)
		}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")

		json.NewEncoder(w).Encode(user)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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

		w.Header().Set("Content-Type", "application/json; charset=UTF-8")

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

		w.Header().Set("Content-Type", "application/json; charset=UTF-8")

		json.NewEncoder(w).Encode(user)

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
