package main

import (
	"encoding/json"
	"errors"
	"github.com/streadway/amqp"
	"log"
	"time"
)

var (
	AMQPChannel *amqp.Channel
)

type AMQPConf struct {
	Queue      string
	Exchange   string
	RoutingKey string
}

func pushToAMQP(task *TaskRequest, aconf *AMQPConf) *MyError {
	// Pushes the given TaskRequest in JSON-form to the given AMQP-queue.
	// On error retries three times before giving up

	msgBody, err := json.Marshal(task)
	if err != nil {
		log.Println("Error while Marshalling: ", err)
		return &MyError{Error: err, Code: ERR_OTHER_RECOVERABLE}
	}
	pub := amqp.Publishing{DeliveryMode: amqp.Persistent, ContentType: "text/plain", Body: msgBody}
	log.Printf("Pushing to %s: \x1b[0;32m%s\x1b[0m\n", aconf.Exchange, msgBody)
	err = AMQPChannel.Publish(aconf.Exchange, aconf.RoutingKey, false, false, pub)

	if err != nil {
		log.Println("Error while pushing to transport: ", err)
		// try to recover three times
		try := 0
		for try < 3 {
			try++
			log.Println("Trying to restore the connection... #", try)
			err = connectAMQP()
			if err == nil {
				break
			}
			// sleep 3 seconds
			time.Sleep(time.Duration(3000000000))
		}
		if err != nil {
			// could not recover the connection after third try => give up
			return &MyError{Error: err, Code: ERR_OTHER_RECOVERABLE}
		}
		log.Println("Connection restored")

		// retry pushing
		err = AMQPChannel.Publish(aconf.Exchange, aconf.RoutingKey, false, false, pub)
		if err != nil {
			return &MyError{Error: err, Code: ERR_OTHER_RECOVERABLE}
		}
	}
	return nil
}

func connectAMQP() error {
	// Create connection to AMQP-server in config
	// Create all Queues and Exchanges from the config

	conn, err := amqp.Dial(conf.AMQP)
	if err != nil {
		return errors.New("Failed to connect to AMQPMQ: " + err.Error())
	}
	//defer conn.Close()

	AMQPChannel, err = conn.Channel()
	if err != nil {
		return errors.New("Failed to open a channel: " + err.Error())
	}
	//defer AMQPChannel.Close()
	addAMQPConf(conf.AMQPDefault)

	for c := range conf.AMQPSplitting {
		err = addAMQPConf(conf.AMQPSplitting[c])
		if err != nil {
			return err
		}
	}

	log.Println("Connected to AMQP")
	return nil
}

func addAMQPConf(c AMQPConf) error {
	// Create Queue and Exchange, and bind Queue to Exchange

	queue, err := AMQPChannel.QueueDeclare(
		c.Queue, //name
		true,    // durable
		false,   // delete when unused
		false,   // exclusive
		false,   // no-wait
		nil,     // arguments
	)
	if err != nil {
		return errors.New("Failed to declare a queue: " + err.Error())
	}

	err = AMQPChannel.ExchangeDeclare(
		c.Exchange, // name
		"topic",    // type
		true,       // durable
		false,      // auto-deleted
		false,      // internal
		false,      // no-wait
		nil,        // arguments
	)
	if err != nil {
		return errors.New("Failed to declare an exchange: " + err.Error())
	}

	err = AMQPChannel.QueueBind(
		queue.Name,   // queue name
		c.RoutingKey, // routing key
		c.Exchange,   // exchange
		false,        // nowait
		nil,          // arguments
	)
	if err != nil {
		return errors.New("Failed to bind queue: " + err.Error())
	}
	return nil
}
