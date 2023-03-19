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

var cognitoClient *cognitoidentityprovider.CognitoIdentityProvider

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

func getLastRequests(db *sql.DB, n int) []struct {
	Ip        string
	Timestamp time.Time
} {
	rows, err := db.Query(`
		SELECT ip, timestamp, user
		FROM userLog
		ORDER BY id DESC
		LIMIT $1
	`, n)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	var requests []struct {
		Ip        string
		Timestamp time.Time
	}

	for rows.Next() {
		var request struct {
			Ip        string
			Timestamp time.Time
		}
		if err := rows.Scan(&request.Ip, &request.Timestamp); err != nil {
			panic(err)
		}
		requests = append(requests, request)
	}

	if err := rows.Err(); err != nil {
		panic(err)
	}

	return requests
}

func main() {

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/signup", signUpHandler)
	http.HandleFunc("/forgot_password", forgotPasswordHandler)

	// Set up AWS session and Cognito client
	//sess := session.Must(session.NewSessionWithOptions(session.Options{
	//	SharedConfigState: session.SharedConfigEnable,
	//}))
	//
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

	// Create table for storing request data
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

		session, err := store.Get(r, "userSession")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if session.Values["authenticated"] != true {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		email, ok := session.Values["email"].(string)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		data := struct {
			Email      string
			InstanceId string
			PrivateIp  string
			Requests   []struct {
				Ip        string
				Timestamp time.Time
			}
		}{
			Email:      email,
			InstanceId: getMetadata("instance-id"),
			PrivateIp:  getMetadata("local-ipv4"),
			Requests:   getLastRequests(db, 5),
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
			<h2>Last 5 Requests:</h2>
			<ul>
			{{range .Requests}}
				<li>{{.Ip}} - {{.Timestamp}}</li>
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

		_, err = db.Exec("INSERT INTO requests (ip, timestamp, email) VALUES ($1, $2, $3)", ip, timestamp, email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Logged request from %s at %s by %s", ip, timestamp, email)
	})

	err = http.ListenAndServe(":80", nil)
	if err != nil {
		log.Println(err)
	} else {
		log.Println("listening on port 80...")
	}

}
