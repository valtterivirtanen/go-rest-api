package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
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
	Password string `json:"password"`
}

type MyError struct {
	Err *MyErrorProps `json:"error"`
}

type MyErrorProps struct {
	Message    string `json:"message"`
	Error      error  `json:"-"`
	StatusCode int    `json:"code"`
}

type JWTToken struct {
	Token string `json:"token"`
}

const secret = "tÃ¤tÃ¤.ei_kukaan|tosta,v44nvoiarvata?EIHÃ„N!?"

var db *sql.DB

func init() {
	checkDbVariable := func(v string) string {
		val, ok := os.LookupEnv(v)
		if !ok {
			fmt.Printf("Environment variable for %v is missing\n", v)
			return ""
		}
		return val
	}

	var connectionString string
	// prefer DABABASE_URL env var
	if val := checkDbVariable("DATABASE_URL"); val != "" {
		connectionString = val
	} else {
		connectionString = fmt.Sprintf(
			"dbname=%v user=%v password=%v host=ec2-79-125-124-30.eu-west-1.compute.amazonaws.com port=5432 sslmode=require",
			checkDbVariable("db_name"), checkDbVariable("db_username"), checkDbVariable("db_password"),
		)
	}
	var err error

	db, err = sql.Open("postgres", connectionString)

	if err != nil {
		panic(err)
	}

	if err = db.Ping(); err != nil {
		panic(err)
	}
	defer fmt.Println("Connection to database established.")

}

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8000"
		log.Printf("Port defaulted to %v", port)
	}
	rtr := mux.NewRouter()

	rtr.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		json.NewEncoder(w).Encode("{'server':'running'}")

	})
	apiRouter := rtr.PathPrefix("/api").Subrouter()

	apiRouter.Handle("/get-token", errorCatcher(getToken)).Methods("POST")

	apiRouter.HandleFunc("/users", authenticationMiddleware(getUsers)).Methods("GET")
	apiRouter.Handle("/users", errorCatcher(createUser)).Methods("POST")
	apiRouter.Handle("/users/{id:[0-9]+}", errorCatcher(getUser)).Methods("GET")
	apiRouter.Handle("/users/{id:[0-9]+}", errorCatcher(updateUser)).Methods("PUT")
	apiRouter.Handle("/users/{id:[0-9]+}", errorCatcher(deleteUser)).Methods("DELETE")

	rtr.NotFoundHandler = http.Handler(errorCatcher(my404Handler))

	log.Fatal(http.ListenAndServe(":"+port, rtr))
}

type errorCatcher func(http.ResponseWriter, *http.Request) *MyError

func (fn errorCatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e := fn(w, r); e != nil {
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		log.Printf("Error: %v\n", e.Err.Error)
		w.WriteHeader(e.Err.StatusCode)
		json.NewEncoder(w).Encode(e)
	}
}

func my404Handler(w http.ResponseWriter, r *http.Request) *MyError {
	return &MyError{&MyErrorProps{"page not found", errors.New("page not found"), 404}}
}

func authenticationMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqToken := r.Header.Get("Authorization")
		if len(reqToken) > 0 {
			splitToken := strings.Split(reqToken, "Bearer ")
			if len(splitToken) > 1 {
				token := JWTToken{splitToken[1]}
				if validateToken(&token) {
					next.ServeHTTP(w, r)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		http.Error(w, "Invalid authorization token", 401)
	}
}

func getToken(w http.ResponseWriter, r *http.Request) *MyError {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	var u User
	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		return &MyError{&MyErrorProps{"invalid request body", err, 400}}
	}
	if len(body) == 0 {
		return &MyError{&MyErrorProps{"empty request body", err, 400}}
	}

	err = json.Unmarshal(body, &u)
	if err != nil {
		return &MyError{&MyErrorProps{"error unmarshalling json", err, 400}}
	}

	//username and password are required
	if len(u.Username) == 0 {
		return &MyError{&MyErrorProps{"provide username, please", err, 400}}
	}
	if len(u.Password) == 0 {
		return &MyError{&MyErrorProps{"provide password, please", err, 400}}
	}

	passwrd := u.Password
	name := u.Username

	valid := validateCredentials(name, passwrd)
	if valid == true {
		token := createToken(name)
		json.NewEncoder(w).Encode(token)
		return nil
	} else {
		return &MyError{&MyErrorProps{"invalid credentials", err, 403}}
	}

}

func createToken(username string) *JWTToken {
	claims := make(jwt.MapClaims)
	claims["name"] = username
	claims["exp"] = time.Now().Add(time.Minute * 10).Unix()

	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)

	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		fmt.Println("error signing token string:", err)
		return nil
	}

	JWTToken := JWTToken{tokenStr}

	return &JWTToken
}

func validateToken(tokenString *JWTToken) bool {
	token, err := jwt.Parse(tokenString.Token, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})

	if err != nil {
		fmt.Println(err)
		return false
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims["name"], claims["exp"], "claims")
		return true
	}
	return false
}

func getUser(w http.ResponseWriter, r *http.Request) *MyError {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	user := User{}
	params := mux.Vars(r)
	id := params["id"]

	if err := db.QueryRow("SELECT id, email, username FROM users WHERE id=$1", id).Scan(&user.ID, &user.Email, &user.Username); err != nil {
		return &MyError{&MyErrorProps{"user not found", err, 404}}
	}

	json.NewEncoder(w).Encode(user)
	return nil
}

func updateUser(w http.ResponseWriter, r *http.Request) *MyError{
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	user := User{}
	params := mux.Vars(r)
	id := params["id"]

	err := db.QueryRow("SELECT id, email, username FROM users WHERE id=$1", id).Scan(&user.ID, &user.Email, &user.Username)
	if err != nil {
		return &MyError{&MyErrorProps{"error quering user", err, 400}}
	}

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

	_, err = db.Exec("UPDATE users SET email=$1, username=$2 WHERE id=$3", user.Email, user.Username, user.ID)
	if err != nil {
		return &MyError{&MyErrorProps{"error updating user", err, 400}}
	}

	json.NewEncoder(w).Encode(user)
	return nil
}

func deleteUser(w http.ResponseWriter, r *http.Request) *MyError {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	user := User{}

	params := mux.Vars(r)
	id := params["id"]

	err := db.QueryRow("DELETE FROM users WHERE id=$1 RETURNING id,username,email", id).Scan(&user.ID, &user.Email, &user.Username)

	if err != nil {
		return &MyError{&MyErrorProps{"error deleting user", err, 400}}
	}

	json.NewEncoder(w).Encode(user)
	return nil
}

func validateCredentials(name string, passwrd string) bool {

	hashedPwd, err := getHashedPassword(name, passwrd)
	if err != nil {
		log.Println("failed to get hashed password", err)
		return false
	}

	err = validPassword(passwrd, hashedPwd)

	if err != nil {
		log.Println("error validating password", err)
		return false
	}

	return true
}

func validPassword(pwd string, hashPwd string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashPwd), []byte(pwd))

	return err
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	users, err := getUsersData()

	if err != nil {
		http.Error(w, "error getting user data: "+err.Error(), http.StatusInternalServerError)
	}

	json.NewEncoder(w).Encode(users)
}

func createUser(w http.ResponseWriter, r *http.Request) *MyError {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")

	var u User

	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		return &MyError{&MyErrorProps{"invalid request body", err, 400}}
	}
	if len(body) == 0 {
		return &MyError{&MyErrorProps{"please provide a request body", err, 400}}
	}

	err = json.Unmarshal(body, &u)
	if err != nil {
		return &MyError{&MyErrorProps{"mashalling failed", err, 400}}
	}

	//username and password are required
	if len(u.Username) == 0 {
		return &MyError{&MyErrorProps{"please provide a username, please", err, 400}}
	}
	if len(u.Password) == 0 {
		return &MyError{&MyErrorProps{"please provide a password, please", err, 400}}
	}
	u.Password, err = hashPwd([]byte(u.Password))
	if err != nil {
		return &MyError{&MyErrorProps{"error hashing password", err, 400}}
	}
	user, err := createUserData(&u)

	if err != nil {
		return &MyError{&MyErrorProps{"error creating user data", err, 400}}
	}

	json.NewEncoder(w).Encode(user)
	return nil
}

func createUserData(u *User) (*User, error) {
	_, err := db.Query("INSERT INTO users(username, email, password) VALUES ($1,$2,$3)", u.Username, u.Email, u.Password)

	if err != nil {
		return nil, err
	}

	user := User{}

	if err = db.QueryRow("SELECT id, email, username FROM users WHERE username=$1 AND password=$2", u.Username, u.Password).Scan(&user.ID, &user.Email, &user.Username); err != nil {
		return nil, err
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

func hashPwd(pwd []byte) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(pwd, 10)

	if err != nil {
		return "", err
	}

	return string(hash), nil
}
