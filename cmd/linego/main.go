package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/CyberTKR/line-go/auth"
	lineclient "github.com/CyberTKR/line-go/client"
	"github.com/CyberTKR/line-go/config"
	"github.com/CyberTKR/line-go/multi"
	"github.com/CyberTKR/line-go/qrdisplay"
	"github.com/CyberTKR/line-go/registration"
	"github.com/CyberTKR/line-go/service"
	"github.com/CyberTKR/line-go/storage"
	"github.com/CyberTKR/line-go/transport"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	if err := run(); err != nil {
		log.Printf("ERROR: %v", err)
		os.Exit(1)
	}
}

func run() error {
	configValue := config.FromEnv()
	command := "qr"
	arguments := os.Args[1:]
	if len(arguments) > 0 && arguments[0][0] != '-' {
		command = arguments[0]
		arguments = arguments[1:]
	}
	flags := flag.NewFlagSet("linego "+command, flag.ContinueOnError)
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: linego <command> [options]")
		fmt.Fprintln(flags.Output(), "Commands: register, qr, profile, refresh, ticket, sync, listen, chats, send, e2ee-check, multi-listen")
		flags.PrintDefaults()
	}
	sessionPath := flags.String("session", configValue.SessionPath, "session JSON file")
	qrFile := flags.String("qr-file", "linego-login-qr.png", "QR PNG file")
	quiet := flags.Bool("qr-quiet", false, "disable terminal QR output")
	workers := flags.Int("workers", 4, "listener worker count")
	count := flags.Int("count", 100, "SYNC4 operation count")
	accountsFile := flags.String("accounts", "accounts.json", "multi-account JSON file")
	ticketUses := flags.Int("uses", 1, "maximum ticket usage count")
	ticketExpiration := flags.Int64("expires", 0, "ticket expiration time (0: unlimited)")
	registrationPhone := flags.String("phone", os.Getenv("LINEGO_REGISTER_PHONE"), "registration phone number")
	registrationRegion := flags.String("region", os.Getenv("LINEGO_REGISTER_REGION"), "two-letter LINE region code")
	displayName := flags.String("display-name", environmentOr("LINEGO_REGISTER_NAME", "LINE User"), "new account display name")
	deviceModel := flags.String("device-model", environmentOr("LINEGO_REGISTER_DEVICE", "SM-S928B"), "Android device model")
	browserExecutable := flags.String("browser", os.Getenv("LINEGO_VERIFICATION_BROWSER"), "Chrome/Chromium executable")
	registrationApplication := flags.String("registration-application", environmentOr("LINEGO_REGISTER_APP", config.DefaultRegistrationApplication), "phone registration Android application identity")
	verificationTimeout := flags.Duration("human-verification-timeout", 5*time.Minute, "manual human verification timeout")
	verificationMethod := flags.String("verification-method", environmentOr("LINEGO_REGISTER_VERIFICATION", "auto"), "phone verification method: auto, sms, or voice")
	simHNI := flags.String("sim-hni", os.Getenv("LINEGO_SIM_HNI"), "SIM HNI/MCC-MNC reported during registration")
	simCarrier := flags.String("sim-carrier", os.Getenv("LINEGO_SIM_CARRIER"), "SIM carrier name reported during registration")
	if len(arguments) > 0 && (arguments[0] == "help" || arguments[0] == "-h" || arguments[0] == "--help") {
		flags.Usage()
		return nil
	}
	if command == "help" {
		flags.Usage()
		return nil
	}
	if err := flags.Parse(arguments); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	configValue.SessionPath = *sessionPath

	switch command {
	case "register":
		return runRegister(configValue, *registrationPhone, *registrationRegion, *displayName, *deviceModel, *registrationApplication, *browserExecutable, *verificationMethod, *simHNI, *simCarrier, *verificationTimeout)
	case "qr":
		return runQR(configValue, *qrFile, *quiet)
	case "profile":
		return runProfile(configValue)
	case "refresh":
		return runRefresh(configValue)
	case "ticket":
		return runTicket(configValue, *ticketExpiration, int32(*ticketUses))
	case "sync":
		return runSync(configValue, int32(*count))
	case "listen":
		if flags.NArg() != 0 {
			return fmt.Errorf("listen does not accept additional arguments")
		}
		return runListen(configValue, int32(*count), *workers)
	case "chats":
		return runChats(configValue)
	case "send":
		if flags.NArg() < 2 {
			return fmt.Errorf("send requires a target MID and message")
		}
		var toType *int32
		if value := os.Getenv("LINEGO_TO_TYPE"); value != "" {
			parsed, err := strconv.ParseInt(value, 10, 32)
			if err != nil {
				return fmt.Errorf("LINEGO_TO_TYPE is invalid: %w", err)
			}
			converted := int32(parsed)
			toType = &converted
		}
		return runSend(configValue, flags.Arg(0), strings.Join(flags.Args()[1:], " "), toType)
	case "e2ee-check":
		return runE2EECheck(configValue)
	case "multi-listen":
		return runMultiListen(configValue, *accountsFile)
	default:
		return fmt.Errorf("unknown command %q (register, qr, profile, refresh, ticket, sync, listen, chats, send, e2ee-check, multi-listen)", command)
	}
}

func runRegister(configValue config.Config, phone, region, displayName, deviceModel, application, browserExecutable, verificationMethod, simHNI, simCarrier string, verificationTimeout time.Duration) error {
	reader := bufio.NewReader(os.Stdin)
	if strings.TrimSpace(region) == "" {
		fmt.Print("Country/region code (for example TW, TH, JP, KR, or HK): ")
		value, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("country/region code could not be read: %w", err)
		}
		region = strings.ToUpper(strings.TrimSpace(value))
	}
	if strings.TrimSpace(phone) == "" {
		fmt.Print("Phone number: ")
		value, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("phone number could not be read: %w", err)
		}
		phone = strings.TrimSpace(value)
	}
	password := os.Getenv("LINEGO_REGISTER_PASSWORD")
	client, err := registration.New(registration.Config{
		Application:         application,
		UserAgent:           configValue.UserAgent,
		Language:            "ja_JP",
		DeviceModel:         deviceModel,
		DisplayName:         displayName,
		Password:            password,
		Timeout:             configValue.Timeout,
		BrowserExecutable:   browserExecutable,
		VerificationMethod:  verificationMethod,
		SIMHNI:              simHNI,
		SIMCarrier:          simCarrier,
		VerificationTimeout: verificationTimeout,
	})
	if err != nil {
		return err
	}
	defer client.Close()
	result, err := client.RegisterPhone(context.Background(), phone, region, func(context.Context) (string, error) {
		fmt.Print("SMS PIN: ")
		return reader.ReadString('\n')
	}, func(event registration.Event) {
		if event.Kind == "human_verification" {
			fmt.Println("[HUMAN VERIFICATION] The official LINE page opened in Chrome; complete verification in the browser.")
			return
		}
		if event.Kind == "human_verification_complete" {
			fmt.Println("[HUMAN VERIFICATION] Accepted; continuing in the same registration session.")
			return
		}
		if event.Step > 0 {
			fmt.Printf("[%d/11] %s\n", event.Step, event.Message)
		}
	})
	if err != nil {
		return err
	}
	refreshAt := int64(0)
	if result.DurationSec > 0 {
		refreshAt = time.Now().Unix() + result.DurationSec
	}
	store := storage.File{Path: configValue.SessionPath}
	if err := store.Save(storage.Session{
		AccessToken:    result.AccessToken,
		RefreshToken:   result.RefreshToken,
		Application:    application,
		UserAgent:      configValue.UserAgent,
		TokenRefreshAt: refreshAt,
		MID:            result.MID,
	}); err != nil {
		return fmt.Errorf("registration completed but the session could not be saved: %w", err)
	}
	fmt.Printf("%s account registered (%s)\n", result.DisplayName, result.MID)
	fmt.Printf("[SESSION] %s\n", store.Path)
	fmt.Println("Tokens and verification authorization were not printed to the console.")
	return nil
}

func environmentOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func runRefresh(configValue config.Config) error {
	client, err := lineclient.Open(configValue)
	if err != nil {
		return err
	}
	defer client.Close()
	ctx := context.Background()
	if err := client.RefreshAccessToken(ctx); err != nil {
		return err
	}
	profile, err := client.GetProfile(ctx)
	if err != nil {
		return fmt.Errorf("token was refreshed but could not be verified: %w", err)
	}
	fmt.Printf("Token refreshed: %s (%s)\n", profile.DisplayName, profile.MID)
	return nil
}

func runTicket(configValue config.Config, expirationTime int64, maxUseCount int32) error {
	client, err := lineclient.Open(configValue)
	if err != nil {
		return err
	}
	defer client.Close()
	ticket, err := client.GenerateUserTicket(context.Background(), expirationTime, maxUseCount)
	if err != nil {
		return err
	}
	fmt.Printf("Bot add link: %s\n", ticket.URL())
	fmt.Printf("Usage limit: %d\n", maxUseCount)
	return nil
}

func runMultiListen(configValue config.Config, path string) error {
	fileConfig, err := multi.Load(path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	manager := multi.Manager{Base: configValue, Accounts: fileConfig.Accounts, Logger: log.Default()}
	return manager.Run(ctx, func(_ context.Context, account string, operation lineclient.Operation, _ *lineclient.Client) error {
		log.Printf("account=%s revision=%d type=%d name=%s", account, operation.Revision, operation.Type, operation.TypeName)
		return nil
	})
}

func runE2EECheck(configValue config.Config) error {
	client, err := lineclient.Open(configValue)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.E2EE.ValidateKeychain(); err != nil {
		return err
	}
	fmt.Println("E2EE device key verified")
	return nil
}

func runChats(configValue config.Config) error {
	client, err := lineclient.Open(configValue)
	if err != nil {
		return err
	}
	defer client.Close()
	chats, err := client.GetChats(context.Background(), nil)
	if err != nil {
		return err
	}
	for _, chat := range chats {
		fmt.Printf("%s\ttype=%d\tmembers=%d\t%s\n", chat.MID, chat.Type, len(chat.Members), chat.Name)
	}
	return nil
}

func runSend(configValue config.Config, to, text string, toType *int32) error {
	client, err := lineclient.Open(configValue)
	if err != nil {
		return err
	}
	defer client.Close()
	message, err := client.SendMessage(context.Background(), to, text, toType)
	if err != nil {
		return err
	}
	fmt.Printf("Message sent: %s\n", message.ID)
	return nil
}

func runQR(configValue config.Config, qrFile string, quiet bool) error {
	store := storage.File{Path: configValue.SessionPath}
	previous, err := store.Load()
	if err != nil {
		return err
	}
	httpClient, err := transport.New(configValue.Host, configValue.Application, configValue.UserAgent, configValue.Language, configValue.Timeout)
	if err != nil {
		return err
	}
	defer httpClient.CloseIdleConnections()
	client := auth.New(service.NewQR(httpClient), service.NewTalk(httpClient))
	credentials, profile, err := client.LoginQR(context.Background(), previous, func(event auth.Event) {
		switch event.Kind {
		case "url":
			path, renderErr := qrdisplay.Render(event.Value, qrFile, os.Stdout, quiet)
			if renderErr != nil {
				log.Printf("QR could not be displayed: %v", renderErr)
				log.Printf("QR link: %s", event.Value)
				return
			}
			fmt.Printf("\n[QR FILE] %s\n", path)
			fmt.Println("Scan the QR code with the LINE app on your phone...")
		case "pin":
			fmt.Printf("\n[PIN] %s\n", event.Value)
			fmt.Println("Confirm this PIN on the LINE screen of the primary device...")
		case "authenticated":
			fmt.Println("\n[AUTHENTICATED] ok")
		}
	})
	if err != nil {
		return err
	}
	if err := store.Save(credentials.Session()); err != nil {
		return fmt.Errorf("login succeeded but the session could not be saved: %w", err)
	}
	name := profile.DisplayName
	if name == "" {
		name = "Unnamed account"
	}
	fmt.Printf("Logged into %s with QR\n", name)
	fmt.Printf("[SESSION] %s\n", store.Path)
	ticketClient, err := lineclient.Open(configValue)
	if err != nil {
		return fmt.Errorf("login succeeded but the ticket client could not be opened: %w", err)
	}
	ticket, ticketErr := ticketClient.GenerateUserTicket(context.Background(), 0, 1)
	ticketClient.Close()
	if ticketErr != nil {
		return fmt.Errorf("login succeeded but the user ticket could not be generated: %w", ticketErr)
	}
	fmt.Printf("[ADD LINK] %s\n", ticket.URL())
	fmt.Println("The link is single-use; open it with LINE and add the bot as a friend.")
	fmt.Println("QR stage completed; the next stage is SYNC4 and the multi-account worker architecture.")
	return nil
}

func runProfile(configValue config.Config) error {
	client, err := lineclient.Open(configValue)
	if err != nil {
		return err
	}
	defer client.Close()
	profile, err := client.GetProfile(context.Background())
	if err != nil {
		return err
	}
	fmt.Printf("%s (%s)\n", profile.DisplayName, profile.MID)
	return nil
}

func runSync(configValue config.Config, count int32) error {
	client, err := lineclient.Open(configValue)
	if err != nil {
		return err
	}
	defer client.Close()
	operations, hasMore, err := client.SyncOnce(context.Background(), count)
	if err != nil {
		return err
	}
	for _, operation := range operations {
		printOperation(operation)
	}
	fmt.Printf("SYNC4 completed operations=%d revision=%d hasMore=%t\n", len(operations), client.Session.SyncState.Revision, hasMore)
	return nil
}

func runListen(configValue config.Config, count int32, workers int) error {
	client, err := lineclient.Open(configValue)
	if err != nil {
		return err
	}
	defer client.Close()
	profile, err := client.GetProfile(context.Background())
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("SYNC4 listener started on %s workers=%d revision=%d", profile.DisplayName, workers, client.Session.SyncState.Revision)
	return client.Listen(ctx, func(_ context.Context, operation lineclient.Operation, _ *lineclient.Client) error {
		printOperation(operation)
		return nil
	}, lineclient.ListenOptions{Count: count, Workers: workers, Logger: log.Default()})
}

func printOperation(operation lineclient.Operation) {
	if operation.Message == nil {
		log.Printf("operation revision=%d type=%d name=%s", operation.Revision, operation.Type, operation.TypeName)
		return
	}
	log.Printf("operation revision=%d type=%d name=%s message_id=%s sender=%s target=%s toType=%d e2ee=%t",
		operation.Revision, operation.Type, operation.TypeName, operation.Message.ID,
		operation.Message.From, operation.Message.To, operation.Message.ToType,
		len(operation.Message.Chunks) > 0,
	)
}
