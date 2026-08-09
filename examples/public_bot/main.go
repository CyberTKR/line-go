package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	lineclient "github.com/CyberTKR/line-go/client"
	"github.com/CyberTKR/line-go/config"
)

const workers = 4

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	client, err := lineclient.Open(config.FromEnv())
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	profile, err := client.GetProfile(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("public bot started on %s mode=SYNC4 workers=%d accepted_op_types=[25,26]", profile.DisplayName, workers)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := client.Listen(ctx, bot, lineclient.ListenOptions{Workers: workers, Count: 100, Logger: log.Default()}); err != nil {
		log.Fatal(err)
	}
}

func bot(ctx context.Context, operation lineclient.Operation, client *lineclient.Client) error {
	if (operation.Type != 25 && operation.Type != 26) || operation.Message == nil {
		return nil
	}
	started := time.Now()
	message := operation.Message
	text, err := client.ResolveMessageText(ctx, message)
	if err != nil {
		return err
	}
	target := message.To
	if operation.Type == 26 && message.ToType == 0 {
		target = message.From
	}
	command := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(text)), ".")
	log.Printf("operation revision=%d type=%d target=%s command=%q e2ee=%t", operation.Revision, operation.Type, target, command, len(message.Chunks) > 0)
	if target == "" {
		return nil
	}
	var reply string
	switch command {
	case "hello":
		reply = "Hello!"
	case "ping":
		reply = "pong"
	default:
		return nil
	}
	toType := message.ToType
	sent, err := client.SendMessage(ctx, target, reply, &toType)
	if err != nil {
		return err
	}
	log.Printf("sendMessage id=%s target=%s elapsed_ms=%.1f", sent.ID, target, float64(time.Since(started).Microseconds())/1000)
	return nil
}
