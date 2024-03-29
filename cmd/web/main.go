package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const webPort = "80"

const mongoPort = "27017"

var client *mongo.Client

func main() {

	key = os.Getenv("SECRETKEY")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	i := 0
	cli, err := mongo.Connect(ctx, options.Client().ApplyURI(fmt.Sprintf("mongodb://mongo:%s", mongoPort)))
	for {

		if err != nil {
			log.Println(err)
			i++
			if i == 10 {
				panic(err)
			}
			time.Sleep(1 * time.Second)
		} else {
			break
		}
		cli, err = mongo.Connect(ctx, options.Client().ApplyURI(fmt.Sprintf("mongodb://mongo:%s", mongoPort)))
	}
	log.Println("CLIENT:", cli, err)
	client = cli
	defer func() {
		if err = client.Disconnect(ctx); err != nil {
			panic(err)
		}
	}()
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", webPort),
		Handler: routes(),
	}

	srv.ListenAndServe()
}
