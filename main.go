package main

import (
	"api/routes"
	"log"
)

func main() {
	router := routes.SetupRouter()

	log.Println("Starting server on :8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
