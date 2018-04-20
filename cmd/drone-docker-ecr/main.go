package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pquerna/otp/totp"
)

func main() {
	var (
		repo      = getenv("PLUGIN_REPO")
		region    = getenv("PLUGIN_REGION", "ECR_REGION", "AWS_REGION")
		key       = getenv("PLUGIN_ACCESS_KEY", "ECR_ACCESS_KEY", "AWS_ACCESS_KEY_ID")
		secret    = getenv("PLUGIN_SECRET_KEY", "ECR_SECRET_KEY", "AWS_SECRET_ACCESS_KEY")
		mfaKey    = getenv("PLUGIN_MFA_KEY", "ECR_MFA_KEY", "AWS_MFA_KEY")
		mfaSerial = getenv("PLUGIN_MFA_SERIAL", "ECR_MFA_SERIAL", "AWS_MFA_SERIAL")
		create    = parseBoolOrDefault(false, getenv("PLUGIN_CREATE_REPOSITORY", "ECR_CREATE_REPOSITORY"))
	)

	// check the region
	if region == "" {
		log.Fatal("You need to specify region")
	}

	os.Setenv("AWS_REGION", region)

	if key != "" && secret != "" {
		log.Printf("Authentication by key/secretKey pair")

		os.Setenv("AWS_ACCESS_KEY_ID", key)
		os.Setenv("AWS_SECRET_ACCESS_KEY", secret)
	}
	if mfaKey != "" && mfaSerial != "" {
		log.Printf("Authentication by MFA")

		// Get one time token to access AWS
		key, err := totp.GenerateCode(mfaKey, time.Now())
		if err != nil {
			log.Fatalf("error in generating one time password: %v", err)
		}

		// Request one time token to AWS
		stsService := sts.New(session.New(&aws.Config{Region: &region}))
		input := &sts.GetSessionTokenInput{
			DurationSeconds: aws.Int64(3600),
			SerialNumber:    aws.String(mfaSerial),
			TokenCode:       aws.String(key),
		}

		// Parse response from AWS
		result, err := stsService.GetSessionToken(input)
		if err != nil {
			if aerr, ok := err.(awserr.Error); ok {
				switch aerr.Code() {
				case sts.ErrCodeRegionDisabledException:
					log.Fatal(sts.ErrCodeRegionDisabledException, aerr.Error())
				default:
					log.Fatalf("error during getting session token (aws error): %v", aerr)
				}
			} else {
				log.Fatalf("error during getting session token: %v", err)
			}
			return
		}

		os.Setenv("AWS_ACCESS_KEY_ID", *result.Credentials.AccessKeyId)
		os.Setenv("AWS_SECRET_ACCESS_KEY", *result.Credentials.SecretAccessKey)
		os.Setenv("AWS_SESSION_TOKEN", *result.Credentials.SessionToken)
	}

	sess, err := session.NewSession(&aws.Config{Region: &region})
	if err != nil {
		log.Fatalf("error creating aws session: %v", err)
	}

	svc := ecr.New(sess)
	username, password, registry, err := getAuthInfo(svc)
	if err != nil {
		log.Fatal(fmt.Sprintf("error getting ECR auth: %v", err))
	}

	if !strings.HasPrefix(repo, registry) {
		repo = fmt.Sprintf("%s/%s", registry, repo)
	}

	if create {
		err = ensureRepoExists(svc, trimHostname(repo, registry))
		if err != nil {
			log.Fatal(fmt.Sprintf("error creating ECR repo: %v", err))
		}
	}

	os.Setenv("PLUGIN_REPO", repo)
	os.Setenv("PLUGIN_REGISTRY", registry)
	os.Setenv("DOCKER_USERNAME", username)
	os.Setenv("DOCKER_PASSWORD", password)

	// invoke the base docker plugin binary
	cmd := exec.Command("drone-docker")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		os.Exit(1)
	}
}

func trimHostname(repo, registry string) string {
	repo = strings.TrimPrefix(repo, registry)
	repo = strings.TrimLeft(repo, "/")
	return repo
}

func ensureRepoExists(svc *ecr.ECR, name string) (err error) {
	input := &ecr.CreateRepositoryInput{}
	input.SetRepositoryName(name)
	_, err = svc.CreateRepository(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == ecr.ErrCodeRepositoryAlreadyExistsException {
			// eat it, we skip checking for existing to save two requests
			err = nil
		}
	}

	return
}

func getAuthInfo(svc *ecr.ECR) (username, password, registry string, err error) {
	var result *ecr.GetAuthorizationTokenOutput
	var decoded []byte

	result, err = svc.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return
	}

	auth := result.AuthorizationData[0]
	token := *auth.AuthorizationToken
	decoded, err = base64.StdEncoding.DecodeString(token)
	if err != nil {
		return
	}

	registry = strings.TrimPrefix(*auth.ProxyEndpoint, "https://")
	creds := strings.Split(string(decoded), ":")
	username = creds[0]
	password = creds[1]
	return
}

func parseBoolOrDefault(defaultValue bool, s string) (result bool) {
	var err error
	result, err = strconv.ParseBool(s)
	if err != nil {
		result = false
	}

	return
}

func getenv(key ...string) (s string) {
	for _, k := range key {
		s = os.Getenv(k)
		if s != "" {
			return
		}
	}
	return
}
