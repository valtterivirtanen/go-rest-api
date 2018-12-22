package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/lib/pq"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

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

const secret = "tÃ¤tÃ¤.ei_kukaan|tosta,v44nvoiarvata?EIHÃ„N!?"

var db *sql.DB

func init() {
	err := error(nil)
	db, err = sql.Open("postgres", os.Getenv("DATABASE_URL"))

	if err != nil {
		panic(err)
	}

	if err = db.Ping(); err != nil {
		panic(err)
	}
	fmt.Println("Connection to database established.")

}

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
	}
	rtr := mux.NewRouter()

	rtr.HandleFunc("/api/get-token", getToken).Methods("POST")

	rtr.HandleFunc("/api/users", getUsers).Methods("GET")
	rtr.HandleFunc("/api/users", createUser).Methods("POST")
	rtr.HandleFunc("/api/users/{id:[0-9]+}", getUser).Methods("GET")
	rtr.HandleFunc("/api/users/{id:[0-9]+}", updateUser).Methods("PUT")
	rtr.HandleFunc("/api/users/{id:[0-9]+}", deleteUser).Methods("DELETE")

	log.Fatal(http.ListenAndServe(":"+port, rtr))
}

func getToken(w http.ResponseWriter, r *http.Request) {

		name := r.FormValue("name")
		passwrd := r.FormValue("password")

		if name != "" && passwrd != "" {

			valid := validateCredentials(name, passwrd)
			if valid == true {
				token := createToken(name)
				w.Header().Set("Content-Type", "application/json; charset=UTF-8")

				json.NewEncoder(w).Encode(token)
			} else {
				http.Error(w, "Invalid credentials", http.StatusForbidden)
			}
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

func getUser(w http.ResponseWriter, r *http.Request) {
	user := User{}
	params := mux.Vars(r)

	id := params["id"]

	if len(id) == 0 {
		http.Error(w, "User not found", http.StatusNotFound)
	}
	if err := db.QueryRow("SELECT id, email, username FROM users WHERE id=$1", id).Scan(&user.ID, &user.Email, &user.Username); err != nil {
		log.Println(err)
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	json.NewEncoder(w).Encode(user)
}

func updateUser(w http.ResponseWriter, r *http.Request) {
	user := User{}

	params := mux.Vars(r)
	id := params["id"]

	err := db.QueryRow("SELECT id, email, username FROM users WHERE id=$1", id).Scan(&user.ID, &user.Email, &user.Username)

	v := params["username"]
	if len(v) > 0 {
		user.Username = v
	}

	v = params["email"]
	if len(v) > 0 {
		user.Email = v
	}

	v = params["password"]
	if len(v) > 0 {
		user.Password = v
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
}

func deleteUser(w http.ResponseWriter, r *http.Request) {
	user := User{}

	params := mux.Vars(r)
	id := params["id"]

	err := db.QueryRow("DELETE FROM users WHERE id=$1 RETURNING id,username,email", id).Scan(&user.ID, &user.Email, &user.Username)

	if err != nil {
		log.Println(err)
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	json.NewEncoder(w).Encode(user)
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

func checkIfError(e error) {
	if e != nil {
		log.Fatalln(e)
	}
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	users, err := getUsersData()

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	json.NewEncoder(w).Encode(users)
}

func createUser(w http.ResponseWriter, r *http.Request) {
	var u User
	if r.Body == nil {
		http.Error(w, "Please send a request body", 400)
		return
	}
	err := json.NewDecoder(r.Body).Decode(&u)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	u.Password = hashPwd([]byte(u.Password))

	user, err := createUserData(&u)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	json.NewEncoder(w).Encode(user)
}

func createUserData(u *User) (*User, error) {
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

func getUsersData() ([]*User, error) {
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
