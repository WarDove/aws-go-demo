package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ssm"
	"log"
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

	testSSMParam, err = getParam(ssmPath + "testSSMParam")
	if err != nil {
		log.Fatalf("Error retrieving value from SSM: %v", err)
	}

}
