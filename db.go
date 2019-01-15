package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
)

var db *sql.DB

func init() {
	checkDbVariable := func(v string) string {
		val, ok := os.LookupEnv(v)
		if !ok {
			log.Fatal("environment variable for " + v + " is missing\n")
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
