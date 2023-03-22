package main

import (
	"database/sql"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func getMetadata(path string) string {
	resp, err := http.Get("http://169.254.169.254/latest/meta-data/" + path)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(body)
}

func getLastRecords(db *sql.DB, n int) []struct {
	Ip        string
	Timestamp time.Time
	Email     string
} {
	rows, err := db.Query(`
		SELECT ip, timestamp, email
		FROM userLog
		ORDER BY id DESC
		LIMIT $1
	`, n)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	var records []struct {
		Ip        string
		Timestamp time.Time
		Email     string
	}

	for rows.Next() {
		var record struct {
			Ip        string
			Timestamp time.Time
			Email     string
		}
		if err := rows.Scan(&record.Ip, &record.Timestamp, &record.Email); err != nil {
			panic(err)
		}
		records = append(records, record)
	}

	if err := rows.Err(); err != nil {
		panic(err)
	}

	return records
}

func main() {

	// Defer DB connection
	defer db.Close()

	// Create table for storing user log data
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS userLog (
			id SERIAL PRIMARY KEY,
			ip TEXT,
			email TEXT,
			timestamp TIMESTAMP
		)
	`)
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/signup", signUpHandler)
	http.HandleFunc("/confirm", confirmHandler)
	http.HandleFunc("/forgot_password", forgotPasswordHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/reset", resetPasswordHandler)
	http.HandleFunc("/log", logHandler)

	err = http.ListenAndServe(":80", nil)
	if err != nil {
		log.Println(err)
	} else {
		log.Println("listening on port 80...")
	}
}
