package main

import (
	_ "cloud.google.com/go/auth/credentials/externalaccount"
	_ "golang.org/x/oauth2/google/externalaccount"
	_ "google.golang.org/api/cloudasset/v1"
	_ "google.golang.org/api/cloudresourcemanager/v3"
	_ "google.golang.org/api/iam/v1"
)

func main() {}
