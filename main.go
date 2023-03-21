package main

import (
	"database/sql"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

var (
	db            *sql.DB
	cognitoClient *cognitoidentityprovider.CognitoIdentityProvider
	testSSMParam  string
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

	log.Printf("starting app... test ssm param: %v", testSSMParam)

	// Set up AWS session and Cognito client
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("eu-west-1"), // replace with your desired region
	})

	cognitoClient = cognitoidentityprovider.New(sess)

	// Set up database connection
	db, err = sql.Open("postgres", "postgres://demouser:demopass@localhost/awsgodemo?sslmode=disable")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Create table for storing user log data
	_, err = db.Exec(`
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

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/signup", signUpHandler)
	http.HandleFunc("/confirm", confirmHandler)
	http.HandleFunc("/forgot_password", forgotPasswordHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/reset", resetPasswordHandler)
	http.HandleFunc("/", mainHandler)

	// TODO: move to handlers once we have ssm solution
	http.HandleFunc("/log", func(w http.ResponseWriter, r *http.Request) {

		// Session cookie AccessToken validation - check user authentication

		session, err := store.Get(r, "userSession")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if session.Values["accessToken"] != nil {
			sessionAccessToken := session.Values["accessToken"].(string)
			params := &cognitoidentityprovider.GetUserInput{
				AccessToken: aws.String(sessionAccessToken),
			}
			_, err = cognitoClient.GetUser(params)
			if err != nil {
				log.Println("Error getting user:", err)
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		} else if session.Values["accessToken"] == nil {
			log.Println("Error getting user:", "accessToken is nil")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		email := session.Values["email"].(string)

		ip := r.RemoteAddr
		timestamp := time.Now().UTC()

		_, err = db.Exec("INSERT INTO userLog (ip, timestamp, email) VALUES ($1, $2, $3)", ip, timestamp, email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := struct {
			Ip        string
			Timestamp time.Time
			Email     string
		}{
			Ip:        ip,
			Timestamp: timestamp,
			Email:     email,
		}

		renderTemplate(w, "log.html", data)
		log.Printf("Logged record from %s at %s by %s", ip, timestamp, email)
	})

	err = http.ListenAndServe(":80", nil)
	if err != nil {
		log.Println(err)
	} else {
		log.Println("listening on port 80...")
	}
}
