# line-go

An experimental Go client for the LINE Android 26.11 protocol, designed for
persistent SYNC4 listeners, E2EE v2 messaging, multi-account workloads, and
editable bot examples.

> This is an unofficial project. Use it only with accounts and groups you are
> authorized to manage. Avoid excessive requests and respect LINE rate limits.

## Features

- QR/PIN login with an atomically saved local session
- Phone registration with LINE's official manual human-verification flow
- Access-token renewal through refresh tokens
- `getProfile`, chat listing, message history, and message-box operations
- Persistent SYNC4 listener with revision recovery and worker pools
- E2EE v2 text decryption and sending for direct and group chats
- Self bot, public bot, and multi-account guard examples
- Configurable endpoints, hosts, application identity, and session paths

## Requirements

- Go 1.23 or newer
- A LINE account you are authorized to use
- Chrome or Chromium when phone registration requires human verification

## Build

```bash
go build -o bin/linego ./cmd/linego
go build -o bin/guard_bot ./examples/guard_bot
```

Generated binaries, sessions, credentials, tokens, local account files, logs,
and QR images are excluded by `.gitignore`.

## QR login

```bash
go run ./cmd/linego qr
```

The command prints a scannable QR code, writes `linego-login-qr.png`, waits for
PIN confirmation when required, and saves the session to
`.linego/session.json` with `0600` permissions. Tokens are never printed.

## Phone registration

The password is read from the environment instead of a command-line argument:

```bash
export LINEGO_REGISTER_PASSWORD='StrongPass9!'
go run ./cmd/linego register \
  --phone 0812345678 \
  --region TH \
  --display-name "LINE User"
```

You can also start registration without command-line options:

```bash
export LINEGO_REGISTER_PASSWORD='StrongPass9!'
go run ./cmd/linego register
```

When no registration options are supplied, the CLI asks only for the required
two-letter country/region code and phone number. It requests the SMS PIN after
LINE sends it. Use `TW` for Taiwan, `TH` for Thailand, `JP` for Japan, `KR` for
Korea, or `HK` for Hong Kong. The display name remains `LINE User`; the device
model and application identity use the built-in Android defaults.

The CLI validates that the mobile-number format matches the selected region
before contacting LINE. It accepts common local and international formats and
prints the expected format when they do not match.

The account password is intentionally not prompted or accepted as a command-line
option. Set `LINEGO_REGISTER_PASSWORD` before starting so it does not appear in
shell history or the process list.

The password must contain at least 8 characters and at least 3 of these 4
categories: an uppercase letter, a lowercase letter, a number, and a symbol.

If LINE returns error `5`, the client opens an isolated browser profile for the
official `https://w.line.me` human-verification flow. Complete the challenge
manually. CAPTCHA solving and verification bypasses are not implemented.
When `HTTPS_PROXY` is configured, Chrome uses the same proxy as the LEGY
registration session. Authenticated proxy credentials remain in the Go process
behind a temporary loopback bridge and are not included in Chrome's command line.

Successful registration stores the access token, refresh token, and session
metadata in `.linego/session.json`. Registration can be customized with
project-specific environment variables:

- `LINEGO_REGISTER_APP` — Android application identity
- `LINEGO_REGISTER_DEVICE` — device model reported to LINE
- `LINEGO_REGISTER_NAME` — default profile display name
- `LINEGO_REGISTER_PHONE` — default phone number
- `LINEGO_REGISTER_REGION` — default two-letter region code
- `LINEGO_VERIFICATION_BROWSER` — Chrome/Chromium executable path
- `LINEGO_SIM_HNI` — SIM HNI/MCC-MNC reported during registration
- `LINEGO_SIM_CARRIER` — SIM carrier name reported during registration

The same values can be supplied explicitly with `--registration-application`,
`--device-model`, `--display-name`, and `--browser`. Use
`--human-verification-timeout 5m` to change the manual challenge timeout.

SMS is selected automatically by default. If LINE reports voice verification
as available, use `--verification-method voice` to receive the PIN through an
automated call. The CLI prints the normalized destination in masked form and
lists the methods returned by LINE. `LINEGO_REGISTER_VERIFICATION` can be set to
`auto`, `sms`, or `voice`.

When SIM metadata is known, provide HNI and carrier together. For example, a
Chunghwa Telecom profile in Taiwan can be supplied as follows:

```bash
export LINEGO_SIM_HNI='46692'
export LINEGO_SIM_CARRIER='Chunghwa'
```

The equivalent CLI options are `--sim-hni 46692 --sim-carrier Chunghwa`. Do not
guess these values when the real mobile carrier is unknown.

## CLI

```bash
go run ./cmd/linego profile
go run ./cmd/linego refresh
go run ./cmd/linego ticket
go run ./cmd/linego sync
go run ./cmd/linego listen --workers 4
go run ./cmd/linego chats
go run ./cmd/linego send <TARGET_CHATID> "hello"
go run ./cmd/linego e2ee-check
```

`refresh` exchanges the stored refresh token for a new access token and saves
rotated credentials atomically. `V3_TOKEN_CLIENT_LOGGED_OUT` indicates a closed
session and requires a new login rather than a normal refresh.

`send` automatically retries with E2EE v2 when the destination requires it or
LINE returns service error `82`.

## Bot examples

```bash
go run ./examples/self_bot
go run ./examples/public_bot
```

The self bot processes only the account's own `op.type 25` messages. The public
bot processes `op.type 25` and `26`. Their command maps are intentionally kept
inside the examples so users can edit behavior directly.

## Multi-account listener

The same `accounts.json` format is used by both the multi-account listener and
the guard bot. Start from the shared example:

```bash
cp accounts.example.json accounts.json
go run ./cmd/linego multi-listen --accounts accounts.json
```

`.linego/session.example.json` documents the session-file structure. Prefer
creating real session files through login instead of editing tokens manually:

```bash
LINEGO_SESSION_PATH=.linego/session.json go run ./cmd/linego qr
LINEGO_SESSION_PATH=.linego/second.json go run ./cmd/linego qr
```

These paths match the two entries in `accounts.example.json`. Add or remove
account entries and session files as needed.

Each account receives an isolated session, HTTP/2 transport, revision stream,
and handler worker pool. Do not place raw tokens in the account configuration;
reference local session files instead.

## Guard bot

```bash
cp accounts.example.json accounts.json
cp .linego/guard.example.json .linego/guard.json
go run ./examples/guard_bot \
  --accounts accounts.json \
  --state .linego/guard.json
```

The example guard state contains no account IDs or group IDs. If `creator` is
left empty, the first user who invites a guard account becomes a Creator.

Validate account profiles and application identities without starting listeners:

```bash
go run ./examples/guard_bot \
  --accounts accounts.json \
  --state .linego/guard.json \
  --check
```

The guard supports persistent roles, group-specific administrators, blacklist
management, protection settings, health-aware account selection, history,
lurk/readers, and time-limited war mode. The first user who invites a guard
account becomes a Creator when the state has no Creator.

Role hierarchy:

```text
Creator > Owner > Admin > GAdmin > User
```

See [GUARD_COMMANDS.md](GUARD_COMMANDS.md) and
[WAR_COMMANDS.md](WAR_COMMANDS.md) for the complete command reference.

## Environment

- `LINEGO_API_HOST`
- `LINEGO_APPLICATION`
- `LINEGO_LANGUAGE`
- `LINEGO_API_TIMEOUT`
- `LINEGO_SESSION_PATH`
- `LINEGO_TO_TYPE`
- `LINEGO_DEBUG=true`

Debug mode logs short SHA-256 fingerprints instead of credential values.

## Project layout

```text
api/           Endpoint and shared Thrift method constants
auth/          QR orchestration and X25519 handling
client/        Profile, chat, message, SYNC4, and listener APIs
config/        Hosts, application identity, defaults, and environment settings
e2ee/          Keychains, AES-CBC/AES-GCM, and key caches
examples/      Editable self, public, and guard bots
guard/         Roles, state, protection, health, and war-mode engine
multi/         Isolated multi-account listener manager
protocol/      Compact and binary Thrift codecs
qrdisplay/     Terminal and PNG QR rendering
registration/  PAIS/LEGY phone registration and manual verification
service/       TalkService, QR, and token-refresh calls
storage/       Atomic session persistence
transport/     Shared HTTP/2 and keep-alive transport
cmd/linego/    Command-line interface
```

## Security

- Never commit `.linego/`, `accounts.json`, `test.json`, `.env`, credential
  exports, private keys, or generated QR images.
- Rotate any credential that has previously been pasted into a chat, log, issue,
  commit, or public repository.
- Keep local session and account files at `0600` permissions.
- Review example configuration before use; it must contain placeholders only.

## Support and contact

If you encounter a problem, find something that should be added, or want to
suggest an improvement, contact the project maintainer:

<a href="mailto:dev@cybertkr.com"><img alt="Email dev@cybertkr.com" src="https://img.shields.io/badge/Email-dev%40cybertkr.com-EA4335?style=for-the-badge&amp;logo=gmail&amp;logoColor=white"></a>
<a href="https://line.me/ti/p/~cybertkr"><img alt="LINE cybertkr" src="https://img.shields.io/badge/LINE-cybertkr-00C300?style=for-the-badge&amp;logo=line&amp;logoColor=white"></a>
