# LINE Guard War Mode Commands

Only a **Creator** or **Owner** can manage war mode. Level 3 can be enabled only
by a Creator. Guard accounts, Creators, Owners, Admins, and GAdmins are always
excluded from war targets.

## Activation and status

- `war on 5m`: Enables war mode for a specified duration between `30s` and
  `24h`.
- `war off`: Disables war mode and strict lock.
- `war status`: Shows the level, remaining time, automatic mode, sensitivity,
  lock, dry-run state, and counters.
- `war dashboard`: Displays the same detailed state as `war status`.
- `war report`: Shows kick, invite, cancel, QR, rescue, error, and suspect
  counters.
- `leader`: Mentions the bots and shows health, membership/invitation state,
  cooldown, E2EE, and revision data. There is no permanent leader; the
  healthiest eligible bot is selected for each event.

## Levels

- `war level 1`: Strictly protects QR access and unauthorized invite/cancel
  activity.
- `war level 2`: Adds attacker removal, blacklist updates, and bot rescue to
  Level 1.
- `war level 3`: Removes new unauthorized joins while war mode is active.
  Creator only.
- `war lock`: Applies strict QR and invitation protection in addition to the
  selected war level.
- `war unlock`: Disables strict lock.

## Automatic mode

- `war auto on|off`: Enables or disables automatic attack detection.
- `war sensitivity low|medium|high`: Sets detection sensitivity.
- `war cooldown 2m`: Sets the quiet period applied after attack activity.

## Whitelist, suspects, and quarantine

- `war whitelist`: Mentions the temporary war whitelist.
- `war whitelist add @user`: Excludes a user from war targets.
- `war whitelist del @user`: Removes the temporary exemption.
- `war suspects`: Mentions users with risk scores and shows their scores.
- `war quarantine @user`: Quarantines a user for ten minutes; they are removed
  if they join during that period.
- `war pardon @user`: Clears the user's risk and quarantine records.
- `war clear`: Clears temporary counters, suspects, and quarantine records.

## Safe testing

- `war dryrun on`: Enables test mode and suppresses Level 3 join removals.
- `war dryrun off`: Restores active enforcement.

## Interaction with normal protection

War mode does not delete existing `kick`, `invite`, `cancel`, or `qr protect`
settings. While active, it temporarily applies stricter enforcement required by
the selected level. The group's normal protection settings remain in effect
after war mode ends.

When a bot is removed, an eligible bot attempts to remove the attacker first
and then recover the missing bot. If no primary bot remains, rescue can start
from accounts held in the invitation list by `ghost 1` or `ghost 2`.
