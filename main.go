package main

import (
	"log"

	"github.com/netlify/gotrue/cmd"
	_ "github.com/netlify/gotrue/docs" // used by go-swagger to find docs
)

func main() {
	if err := cmd.RootCommand().Execute(); err != nil {
		log.Fatal(err)
	}
}
