package main

import (
	"fmt"
	"github.com/rgooding/authproxy/auth"
	"os"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Printf("Usage: %s plaintext-password\n", os.Args[0])
		os.Exit(1)
	}

	hash, err := auth.HashPassword(os.Args[1])
	if err != nil {
		fmt.Printf("Error hashing passowrd: %s\n", err.Error())
		os.Exit(1)
	}
	fmt.Println(hash)
}
