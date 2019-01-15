package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type JWTToken struct {
	Token string `json:"token"`
}

func getToken(w http.ResponseWriter, r *http.Request) *MyError {

	var u User
	body, err := ioutil.ReadAll(r.Body)

	if err != nil {
		return &MyError{&MyErrorProps{"invalid request body", err, 400, ""}}
	}
	if len(body) == 0 {
		return &MyError{&MyErrorProps{"empty request body", err, 400, ""}}
	}

	err = json.Unmarshal(body, &u)
	if err != nil {
		return &MyError{&MyErrorProps{"error unmarshalling json", err, 400, ""}}
	}

	//username and password are required
	if len(u.Username) == 0 {
		return &MyError{&MyErrorProps{"provide username, please", err, 400, ""}}
	}
	if len(u.Password) == 0 {
		return &MyError{&MyErrorProps{"provide password, please", err, 400, ""}}
	}

	passwrd := u.Password
	name := u.Username

	valid := validateCredentials(name, passwrd)
	if valid == false {
		return &MyError{&MyErrorProps{"invalid credentials", err, 403, ""}}
	}
	token, err := createToken(name)
	if err != nil {
		return &MyError{&MyErrorProps{"error signing token string", err, 403, ""}}
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

func authenticationMiddleware(next http.Handler) http.Handler {
	return http.Handler(errorCatcher(func(w http.ResponseWriter, r *http.Request) *MyError {
		reqToken := r.Header.Get("Authorization")
		if len(reqToken) == 0 {
			return &MyError{&MyErrorProps{"authorization header missing", errors.New("authorization header missing"), 401, ""}}
		}
		splitToken := strings.Split(reqToken, "Bearer ")
		if len(splitToken) <= 1 {
			return &MyError{&MyErrorProps{"invalid authorization token", errors.New("invalid authorization token"), 401, ""}}

		}
		token := JWTToken{splitToken[1]}
		if err := validateToken(&token); err != nil {
			return &MyError{&MyErrorProps{"invalid authorization token", err, 401, ""}}
		}
		next.ServeHTTP(w, r)
		return nil
	}))
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
