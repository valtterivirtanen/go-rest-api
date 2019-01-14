package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"mime"
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
			log.Fatal("Environment variable for %v is missing\n", v)
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
		log.Printf("Port defaulted to %v\n", port)
	}
	rtr := mux.NewRouter()

	rtr.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		in = make(map[string]string)
		in["server"] = "running"
		json.NewEncoder(w).Encode(in)

	}).Methods("GET")
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

type errorCatcher func(http.ResponseWriter, *http.Request) *MyError

func (fn errorCatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e := fn(w, r); e != nil {

		log.Printf("Error: %v\n", e.Err.Error)
		w.WriteHeader(e.Err.StatusCode)
		json.NewEncoder(w).Encode(e)
	}
}

func my404Handler(w http.ResponseWriter, r *http.Request) *MyError {
	return &MyError{&MyErrorProps{"page not found", errors.New("page not found: " + r.URL.String()), 404}}
}

func my405Handler(w http.ResponseWriter, r *http.Request) *MyError {
	return &MyError{&MyErrorProps{"method not allowed", errors.New("method not allowed: " + r.Method), 405}}
}

func authenticationMiddleware(next http.Handler) http.Handler {
	return http.Handler(errorCatcher(func(w http.ResponseWriter, r *http.Request) *MyError {
		reqToken := r.Header.Get("Authorization")
		if len(reqToken) == 0 {
			return &MyError{&MyErrorProps{"authorization header missing", errors.New("authorization header missing"), 401}}
		}
		splitToken := strings.Split(reqToken, "Bearer ")
		if len(splitToken) <= 1 {
			return &MyError{&MyErrorProps{"invalid authorization token", errors.New("invalid authorization token"), 401}}

		}
		token := JWTToken{splitToken[1]}
		if err := validateToken(&token); err != nil {
			return &MyError{&MyErrorProps{"invalid authorization token", err, 401}}
		}
		next.ServeHTTP(w, r)
		return nil
	}))
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
		if m, _, err := mime.ParseMediaType(ct); m != "application/json" {
			return &MyError{&MyErrorProps{"invalid content-type", err, 400}}
		}
		next.ServeHTTP(w, r)

		return nil
	}))
}

func myLoggerMiddleware(next http.Handler) http.Handler {
	return http.Handler(errorCatcher(func(w http.ResponseWriter, r *http.Request) *MyError {
		t := time.Now().Format(time.RFC3339)

		ua := r.Header.Get("User-Agent")
		mthd := r.Method
		url := r.URL.String()

		text := fmt.Sprintf("%s %s %s %s\n", t, mthd, url, ua)

		f, err := os.OpenFile("log.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return &MyError{&MyErrorProps{"opening log file failed", err, 400}}
		}

		defer f.Close()

		if _, err = f.WriteString(text); err != nil {
			return &MyError{&MyErrorProps{"writing log file failed", err, 400}}

		}
		next.ServeHTTP(w, r)

		return nil
	}))
}

func getToken(w http.ResponseWriter, r *http.Request) *MyError {

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
	if valid == false {
		return &MyError{&MyErrorProps{"invalid credentials", err, 403}}
	}
	token, err := createToken(name)
	if err != nil {
		return &MyError{&MyErrorProps{"error signing token string", err, 403}}
	}
	json.NewEncoder(w).Encode(token)
	return nil
}

func createToken(username string) (*JWTToken, error) {
	claims := make(jwt.MapClaims)
	claims["name"] = username
	claims["exp"] = time.Now().Add(time.Minute * 10).Unix()

	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), claims)

	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		return nil, err
	}

	JWTToken := JWTToken{tokenStr}

	return &JWTToken, nil
}

func validateToken(tokenString *JWTToken) error {
	token, err := jwt.Parse(tokenString.Token, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})

	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return nil
	}
	return errors.New("invalid token")
}

func getUser(w http.ResponseWriter, r *http.Request) *MyError {

	user := User{}
	params := mux.Vars(r)
	id := params["id"]

	if err := db.QueryRow("SELECT id, email, username FROM users WHERE id=$1", id).Scan(&user.ID, &user.Email, &user.Username); err != nil {
		return &MyError{&MyErrorProps{"user not found", err, 404}}
	}

	json.NewEncoder(w).Encode(user)
	return nil
}

func updateUser(w http.ResponseWriter, r *http.Request) *MyError {

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

func getUsers(w http.ResponseWriter, r *http.Request) *MyError {

	users, err := getUsersData()

	if err != nil {
		return &MyError{&MyErrorProps{"error getting user data", err, 400}}
	}

	json.NewEncoder(w).Encode(users)
	return nil
}

func createUser(w http.ResponseWriter, r *http.Request) *MyError {

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
