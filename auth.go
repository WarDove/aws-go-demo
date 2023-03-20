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
	"log"
	"net/http"
	"text/template"
)

var (
	appClientID     string = "q62763s8s2hhk0hsdtge82f7a"
	appClientSecret string = "1df1cvo0m97ipc8q793knjmd82tmc8gn94f7fn4n0t0o093b1ibb"
	store                  = sessions.NewCookieStore([]byte("someverysecretkey")) // TODO: store as secret!
	templates              = template.Must(template.ParseFiles(
		"templates/signup.html", "templates/login.html", "templates/confirm.html", "templates/forgot_password.html",
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
		confirmPassword := r.FormValue("confirm_password")

		if password != confirmPassword {
			log.Printf("Passwords do not match, signup event for %s\n", email)
			data := struct {
				Error string
			}{
				Error: "Passwords do not match",
			}
			renderTemplate(w, "signup.html", data)
			return
		}

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
			log.Println(err.Error())
			data := struct {
				Error string
			}{
				Error: err.Error(),
			}
			renderTemplate(w, "signup.html", data)
			return
		}

		// Render the confirmation code form
		renderTemplate(w, "confirm.html", map[string]interface{}{
			"email": email,
		})
	} else {
		// Render the sign-up form
		renderTemplate(w, "signup.html", nil)
	}
}

func confirmHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		email := r.FormValue("email")
		conformationCode := r.FormValue("conformationCode")

		// Calculate the SecretHash
		secretHash := createSecretHash(email, appClientID, appClientSecret)

		_, err := cognitoClient.ConfirmSignUp(&cognitoidentityprovider.ConfirmSignUpInput{
			ClientId:         &appClientID,
			Username:         &email,
			ConfirmationCode: &conformationCode,
			SecretHash:       &secretHash,
		})

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			http.Error(w, "Passwords do not match", http.StatusBadRequest)
			data := struct {
				Error error
			}{
				Error: err,
			}
			renderTemplate(w, "confirm.html", data)
			return
		}
		fmt.Fprintf(w, "Confirmation successful!")

	} else {
		// Render the confirmation form
		renderTemplate(w, "confirm.html", nil)
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

	// Session cookie AccessToken validation - check user authentication
	session, err := store.Get(r, "userSession")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionAccessToken := session.Values["accessToken"].(string)

	if sessionAccessToken != "" {
		params := &cognitoidentityprovider.GetUserInput{
			AccessToken: aws.String(sessionAccessToken),
		}

		resp, err := cognitoClient.GetUser(params)
		if err != nil {
			log.Println("Error getting user:", err)
		} else {
			http.Redirect(w, r, "/", http.StatusFound)
			log.Printf("Get user output: \n%v", resp)
			// Getting attributes and Group from user
			//userAttributes := resp.UserAttributes
			//groups := resp.GroupMembership
			return
		}
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

	// Calculate the SecretHash
	secretHash := createSecretHash(email, appClientID, appClientSecret)

	// Authenticate user
	authParams := &cognitoidentityprovider.InitiateAuthInput{
		AuthFlow: aws.String("USER_PASSWORD_AUTH"),
		AuthParameters: map[string]*string{
			"USERNAME":    aws.String(email),
			"PASSWORD":    aws.String(password),
			"SECRET_HASH": aws.String(secretHash),
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
		renderTemplate(w, "login.html", data)
		return
	}

	// Set session cookie
	session.Values["email"] = email
	session.Values["accessToken"] = *authResult.AuthenticationResult.AccessToken
	//session.Values["idToken"] = authResult.AuthenticationResult.IdToken

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}
