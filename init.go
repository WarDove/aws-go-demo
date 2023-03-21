package main

import (
	"database/sql"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/gorilla/sessions"
	"log"
	"text/template"
)

var (
	appClientID     string
	appClientSecret string
	sessionStore    *sessions.CookieStore
	templates       *template.Template
	db              *sql.DB
	cognitoClient   *cognitoidentityprovider.CognitoIdentityProvider
)

func getParam(name string) (value string, err error) {

	ssmSession := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
		Config: aws.Config{
			Region: aws.String("eu-west-1"),
		},
	}))

	ssmSvc := ssm.New(ssmSession)

	param, err := ssmSvc.GetParameter(&ssm.GetParameterInput{
		Name:           aws.String(name),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		return "", err
	}

	return *param.Parameter.Value, nil
}

func init() {

	var err error

	ssmPath := "/go-demo/"

	appClientID, err = getParam(ssmPath + "appClientID")
	if err != nil {
		log.Fatalf("Error retrieving value from SSM: %v", err)
	}

	appClientSecret, err = getParam(ssmPath + "appClientSecret")
	if err != nil {
		log.Fatalf("Error retrieving value from SSM: %v", err)
	}

	sessionEnryptSecret, err := getParam(ssmPath + "sessionEnryptSecret")
	if err != nil {
		log.Fatalf("Error retrieving value from SSM: %v", err)
	}

	sessionStore = sessions.NewCookieStore([]byte(sessionEnryptSecret))

	templates = template.Must(template.ParseFiles(
		"templates/reset_password.html", "templates/log.html", "templates/index.html", "templates/signup.html", "templates/login.html", "templates/confirm.html", "templates/forgot_password.html",
	))

	// Set up AWS session and Cognito client
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("eu-west-1"),
	})

	cognitoClient = cognitoidentityprovider.New(sess)

	// Set up database connection
	db, err = sql.Open("postgres", "postgres://demouser:demopass@localhost/awsgodemo?sslmode=disable") // TODO: store as secret!
	if err != nil {
		panic(err)
	}
	defer db.Close()
}
