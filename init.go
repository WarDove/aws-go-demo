package main

import (
	"database/sql"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go/service/ssm"
	"github.com/gorilla/sessions"
	"os"
	"text/template"
)

var (
	region          string = getMetadata("placement/region")
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
			Region: aws.String(region),
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

	appClientID = os.Getenv("APP_CLIENT_ID")
	appClientSecret = os.Getenv("APP_CLIENT_SECRET")
	sessionEncryptSecret := os.Getenv("SESSION_ENCRYPTION_SECRET")
	dbHost := os.Getenv("DB_HOST")
	dbEngine := os.Getenv("DB_ENGINE")
	dbName := os.Getenv("DB_NAME")
	dbUserName := os.Getenv("DB_USERNAME")
	dbPassword := os.Getenv("DB_PASSWORD")

	sessionStore = sessions.NewCookieStore([]byte(sessionEncryptSecret))

	templates = template.Must(template.ParseFiles(
		"templates/reset_password.html", "templates/log.html", "templates/index.html", "templates/signup.html", "templates/login.html", "templates/confirm.html", "templates/forgot_password.html",
	))

	// Set up AWS session and Cognito client
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})

	cognitoClient = cognitoidentityprovider.New(sess)

	// Set up database connection
	dataSourceName := fmt.Sprintf("%s://%s:%s@%s/%s?sslmode=disable", dbEngine, dbUserName, dbPassword, dbHost, dbName)
	db, err = sql.Open(dbEngine, dataSourceName)
	if err != nil {
		panic(err)
	}
}
