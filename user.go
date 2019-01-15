package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func getUser(w http.ResponseWriter, r *http.Request) *MyError {

	user := User{}
	params := mux.Vars(r)
	id := params["id"]

	if err := db.QueryRow("SELECT id, email, username FROM users WHERE id=$1", id).Scan(&user.ID, &user.Email, &user.Username); err != nil {
		return &MyError{&MyErrorProps{"user not found", err, 404, ""}}
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
		return &MyError{&MyErrorProps{"error quering user", err, 400, ""}}
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
		return &MyError{&MyErrorProps{"error updating user", err, 400, ""}}
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
		return &MyError{&MyErrorProps{"error deleting user", err, 400, ""}}
	}

	json.NewEncoder(w).Encode(user)
	return nil
}

func getUsers(w http.ResponseWriter, r *http.Request) *MyError {

	users, err := getUsersData()

	if err != nil {
		return &MyError{&MyErrorProps{"error getting user data", err, 400, ""}}
	}

	json.NewEncoder(w).Encode(users)
	return nil
}

func createUser(w http.ResponseWriter, r *http.Request) *MyError {

	var u User

	body, err := ioutil.ReadAll(r.Body)

	if err != nil || len(body) == 0 {
		return &MyError{&MyErrorProps{"invalid request body", err, 400, ""}}
	}

	err = json.Unmarshal(body, &u)
	if err != nil {
		return &MyError{&MyErrorProps{"request body not a valid JSON", err, 400, ""}}
	}

	//username and password are required
	if len(u.Username) == 0 {
		return &MyError{&MyErrorProps{"please provide a username, please", err, 400, ""}}
	}
	if len(u.Password) == 0 {
		return &MyError{&MyErrorProps{"please provide a password, please", err, 400, ""}}
	}
	bytePassword := []byte(u.Password)
	tempPassword, err := bcrypt.GenerateFromPassword(bytePassword, 10)
	u.Password = string(tempPassword)
	if err != nil {
		return &MyError{&MyErrorProps{"error hashing password", err, 400, ""}}
	}
	user, err := createUserData(&u)

	if err != nil {
		return &MyError{&MyErrorProps{"error creating user data", err, 400, ""}}
	}

	json.NewEncoder(w).Encode(user)
	return nil
}
