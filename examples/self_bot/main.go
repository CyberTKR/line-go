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
	log.Printf("self bot started on %s mid=%s mode=SYNC4 workers=%d accepted_op_types=[25]", profile.DisplayName, profile.MID, workers)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = client.Listen(ctx, bot, lineclient.ListenOptions{Workers: workers, Count: 100, Logger: log.Default()})
	if err != nil {
		log.Fatal(err)
	}
}

func bot(ctx context.Context, operation lineclient.Operation, client *lineclient.Client) error {
	log.Printf("operation revision=%d type=%d name=%s", operation.Revision, operation.Type, operation.TypeName)
	if operation.Type != 25 || operation.Message == nil {
		return nil
	}
	message := operation.Message
	if message.From != client.Session.MID {
		return nil
	}
	started := time.Now()
	text, err := client.ResolveMessageText(ctx, message)
	if err != nil {
		return err
	}
	log.Printf("received op.type=25 target=%s e2ee=%t", message.To, len(message.Chunks) > 0)
	if err := runCommand(ctx, client, message, text); err != nil {
		return err
	}
	log.Printf("operation completed revision=%d elapsed_ms=%.1f", operation.Revision, float64(time.Since(started).Microseconds())/1000)
	return nil
}

func runCommand(ctx context.Context, client *lineclient.Client, message *lineclient.Message, text string) error {
	command := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(text)), ".")
	switch command {
	case "hello":
		return sendText(ctx, client, message, message.To, "Hello!")
	case "ping":
		return sendText(ctx, client, message, message.To, "pong")
	case "ginfo":
		if message.ToType != 2 {
			return sendText(ctx, client, message, message.To, "This command only works in groups.")
		}
		chats, err := client.GetChats(ctx, []string{message.To})
		if err != nil || len(chats) == 0 {
			return err
		}
		chat := chats[0]
		info := "[GROUP INFO]\nName: " + chat.Name + "\nMID: " + chat.MID + "\nMembers: " + itoa(len(chat.Members))
		return sendText(ctx, client, message, message.To, info)
	default:
		return nil
	}
}

func sendText(ctx context.Context, client *lineclient.Client, source *lineclient.Message, target, text string) error {
	toType := source.ToType
	message, err := client.SendMessage(ctx, target, text, &toType)
	if err == nil {
		log.Printf("sendMessage id=%s target=%s toType=%d", message.ID, target, toType)
	}
	return err
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := make([]byte, 0, 8)
	for value > 0 {
		digits = append(digits, byte('0'+value%10))
		value /= 10
	}
	for left, right := 0, len(digits)-1; left < right; left, right = left+1, right-1 {
		digits[left], digits[right] = digits[right], digits[left]
	}
	return string(digits)
}
