package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	lineclient "github.com/CyberTKR/line-go/client"
	"github.com/CyberTKR/line-go/config"
	"github.com/CyberTKR/line-go/guard"
	"github.com/CyberTKR/line-go/multi"
)

func main() {
	cpu := runtime.NumCPU()
	runtime.GOMAXPROCS(cpu)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	accountsPath := flag.String("accounts", "accounts.json", "bot account session list")
	statePath := flag.String("state", ".linego/guard.json", "shared protection and permission state")
	checkOnly := flag.Bool("check", false, "validate accounts with getProfile and exit")
	flag.Parse()

	accounts, err := multi.Load(*accountsPath)
	if err != nil {
		log.Fatal(err)
	}
	store, err := guard.OpenStore(*statePath)
	if err != nil {
		log.Fatal(err)
	}
	engine := guard.NewEngine(store, log.Default())
	if !*checkOnly {
		engine.SetExpectedClients(len(accounts.Accounts))
	}
	roles := make(map[string]string, len(accounts.Accounts))
	for _, account := range accounts.Accounts {
		roles[account.Name] = account.Role
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	manager := multi.Manager{
		Base: config.FromEnv(), Accounts: accounts.Accounts, Logger: log.Default(),
		OnReady: func(account string, client *lineclient.Client) error {
			if err := engine.RegisterClient(ctx, account, roles[account], client); err != nil {
				return err
			}
			log.Printf("guard account=%s bot_mid=%s registered", account, client.Session.MID)
			return nil
		},
	}
	state := store.Snapshot()
	if *checkOnly {
		if err := manager.Check(context.Background()); err != nil {
			log.Fatal(err)
		}
		log.Printf("guard account check completed; listener/moderation not started")
		return
	}
	log.Printf("guard started accounts=%d creators=%q owners=%d admins=%d groups=%d gomaxprocs=%d", len(accounts.Accounts), state.Creators, len(state.Owners), len(state.Admins), len(state.Groups), cpu)
	if len(state.Creators) == 0 {
		log.Printf("creator is not set; the first user who invites the bot via op.type 124 becomes creator")
	}
	if err := manager.Run(ctx, engine.Handle); err != nil {
		log.Fatal(err)
	}
}
