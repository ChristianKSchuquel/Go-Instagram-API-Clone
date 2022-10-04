package main

import (
	"api2/database"
	"api2/routers"
	"log"
)

func main() {
	database.Setup()
	r := routers.Setup()
	if err := r.Run(":3000"); err != nil {
		log.Fatal(err)
	}
}
