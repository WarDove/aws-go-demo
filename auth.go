package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"net/http"
	"text/template"
)

var (
	appClientID     string = "q62763s8s2hhk0hsdtge82f7a"
	appClientSecret string = "1df1cvo0m97ipc8q793knjmd82tmc8gn94f7fn4n0t0o093b1ibb"
	store                  = sessions.NewCookieStore([]byte("someverysecretkey"))
	templates              = template.Must(template.ParseFiles(
		"templates/signup.html", "templates/login.html", "templates/forgot_password.html",
	))
)

func renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	tmpl, err := templates.Lookup(name).Clone()
	if err != nil {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func createSecretHash(username, clientID, clientSecret string) string {
	message := []byte(username + clientID)
	key := []byte(clientSecret)
	h := hmac.New(sha256.New, key)
	_, err := h.Write(message)
	if err != nil {
		return ""
	}
	hash := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return hash
}

func signUpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Calculate the SecretHash
		secretHash := createSecretHash(email, appClientID, appClientSecret)

		// Create the user in Cognito
		_, err := cognitoClient.SignUp(&cognitoidentityprovider.SignUpInput{
			ClientId:   &appClientID,
			Username:   &email,
			Password:   &password,
			SecretHash: &secretHash,
			UserAttributes: []*cognitoidentityprovider.AttributeType{
				{
					Name:  aws.String("email"),
					Value: &email,
				},
			},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Sign-up successful!")
	} else {
		// Render the sign-up form
		renderTemplate(w, "signup.html", nil)
	}
}

func forgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")

		// Initiate the forgot password flow in Cognito
		_, err := cognitoClient.ForgotPassword(&cognitoidentityprovider.ForgotPasswordInput{
			ClientId: &appClientID,
			Username: &email,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "Password reset email sent!")
	} else {
		// Render the forgot password form
		renderTemplate(w, "forgot_password.html", nil)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is already authenticated
	session, err := store.Get(r, "userSession")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if session.Values["authenticated"] == true {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	// Get form data
	email := r.FormValue("email")
	password := r.FormValue("password")

	// Validate form data
	if email == "" || password == "" {
		data := struct {
			Error string
		}{
			Error: "Please enter your email and password",
		}
		renderTemplate(w, "login.html", data)
		return
	}

	// Authenticate user
	authParams := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),
		AuthParameters: map[string]*string{
			"USERNAME": aws.String(email),
			"PASSWORD": aws.String(password),
		},
		ClientId: aws.String(appClientID),
	}
	authResult, err := cognitoClient.InitiateAuth(authParams)
	if err != nil {
		data := struct {
			Error string
		}{
			Error: err.Error(),
		}
		renderTemplate(w, "login", data)
		return
	}

	// Set session cookie
	session.Values["authenticated"] = true
	session.Values["accessToken"] = *authResult.AuthenticationResult.AccessToken
	session.Values["idToken"] = authResult.AuthenticationResult.IdToken
	session.Values["email"] = email
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	//can := *authResult.AuthenticationResult.IdToken

	http.Redirect(w, r, "/", http.StatusFound)
}
