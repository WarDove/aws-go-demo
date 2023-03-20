package main

import (
	"database/sql"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

var (
	cognitoClient *cognitoidentityprovider.CognitoIdentityProvider
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

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/signup", signUpHandler)
	http.HandleFunc("/confirm", confirmHandler)
	http.HandleFunc("/forgot_password", forgotPasswordHandler)

	// Extend cookie size to 8KB

	// Set up AWS session and Cognito client
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("eu-west-1"), // replace with your desired region
	})

	cognitoClient = cognitoidentityprovider.New(sess)

	// Set up database connection
	db, err := sql.Open("postgres", "postgres://demouser:demopass@localhost/awsgodemo?sslmode=disable")
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

	// Define route handlers
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		// Session cookie AccessToken validation - check user authentication
		session, err := store.Get(r, "userSession")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		sessionAccessToken := session.Values["accessToken"].(string)

		params := &cognitoidentityprovider.GetUserInput{
			AccessToken: aws.String(sessionAccessToken),
		}

		resp, err := cognitoClient.GetUser(params)
		if err != nil {
			log.Println("Error getting user:", err)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		log.Printf("Get user output: \n%v", resp)
		// Getting attributes and Group from user
		//userAttributes := resp.UserAttributes
		//groups := resp.GroupMembership

		email, ok := session.Values["email"].(string)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		data := struct {
			Email      string
			InstanceId string
			PrivateIp  string
			Records    []struct {
				Ip        string
				Timestamp time.Time
				Email     string
			}
		}{
			Email:      email,
			InstanceId: getMetadata("instance-id"),
			PrivateIp:  getMetadata("local-ipv4"),
			Records:    getLastRecords(db, 5),
		}

		tmpl, err := template.New("index").Parse(`
		<!doctype html>
		<html>
		<head><title>EC2 Instance Metadata</title></head>
		<body>
			<h2>User Email: {{.Email}}</h2>
			<h1>EC2 Instance Metadata</h1>
			<p><strong>Instance ID:</strong> {{.InstanceId}}</p>
			<p><strong>Private IP:</strong> {{.PrivateIp}}</p>
			<h2>Last 5 log entries:</h2>
			<ul>
			{{range .Records}}
				<li>SourceIP: {{.Ip}}, Timestamp: {{.Timestamp}}, User Email: {{.Email}} </li>
			{{end}}
			</ul>
			<form method="POST" action="/log">
				<button type="submit">LOG</button>
			</form>
		</body>
		</html>
		`)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	http.HandleFunc("/log", func(w http.ResponseWriter, r *http.Request) {

		session, err := store.Get(r, "userSession")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if session.Values["authenticated"] != true {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		ip := r.RemoteAddr
		timestamp := time.Now().UTC()
		email := session.Values["email"]

		_, err = db.Exec("INSERT INTO userLog (ip, timestamp, email) VALUES ($1, $2, $3)", ip, timestamp, email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Logged record from %s at %s by %s", ip, timestamp, email)
	})

	err = http.ListenAndServe(":80", nil)
	if err != nil {
		log.Println(err)
	} else {
		log.Println("listening on port 80...")
	}
}
