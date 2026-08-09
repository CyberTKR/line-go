# LINE Guard Command Guide

Guard commands must be sent **without a leading dot**. The guard ignores
`.help`, `.kick`, and `.war on`; use `help`, `kick`, and `war on` instead.

## Tests and status

- `ping`: Every active guard replies with `pong`.
- `speed`: Every active guard reports its message-processing latency.
- `status`: Mentions each bot and shows whether it is active, in the group,
  invited, or outside, plus cooldown, E2EE, and revision information. Requires
  GAdmin or higher.
- `bots`: Mentions the bots and shows their basic health. Requires GAdmin or
  higher.
- `bot health` or `health`: Shows kick, invite, cancel, success, error, and
  cooldown counters. Requires Admin or higher.
- `leader`: Shows detailed bot state. War mode does not use a permanent leader;
  the healthiest eligible bot is selected for each action.

## Group protection

- `protect on|off`: Enables or disables invite, cancel, kick, and QR protection
  together.
- `invite protect on|off`: Cancels unauthorized invitations and penalizes the
  inviter when enabled.
- `cancel protect on|off`: Penalizes users who cancel invitations without
  permission.
- `kick protect on|off`: Penalizes unauthorized kick actors. Regular users who
  were removed are not automatically reinvited.
- `qr protect on|off`: Closes unauthorized group ticket/QR access and penalizes
  the actor who opened it.
- `all protect on|off`: Limits unauthorized native `@All` usage. The first
  violation produces a warning; a repeated violation within the configured
  window results in removal.
- `flood protect on|off`: Limits message, sticker, and mention spam. The first
  violation produces a warning; repeated abuse results in removal.
- `protect status`: Shows invite, cancel, kick, QR, all, and flood settings in a
  single response.

Protection is disabled by default in new or unconfigured groups. Creators,
Owners, Admins, GAdmins, and registered guard accounts are exempt.

## Member actions

- `kick @user`: Removes a mentioned regular member. Bots and authorized users
  cannot be targeted. Requires GAdmin or higher.
- `kickall`: Distributes all eligible members across the guard accounts and
  removes them. Bots and authorized users are excluded. Requires Admin or
  higher.
- `invite @user`: Invites a user to the group. A GAdmin cannot invite a bot.
- `blacklist @user`: Adds a user to the blacklist and removes them when
  possible. Requires Admin or higher.
- `blacklist`: Shows the blacklist using display names and mentions.
- `unban @user`: Removes a user from the blacklist. Requires GAdmin or higher.
- `clear blacklist` or `clearban`: Clears the blacklist and reports the number
  of deleted entries. Requires Admin or higher.
- `add me`: Attempts to add the requesting Creator or Owner to every guard
  account's friend list.
- `ticket`: Returns the add-friend links for the guard accounts.

## Role management

- `add creator @user`: Adds a Creator. Creator only.
- `del creator @user`: Removes a Creator. The final Creator and the Creator
  issuing the command cannot be removed.
- `add owner @user`: Adds an Owner. Creator only.
- `del owner @user`: Removes an Owner. Creator only.
- `add admin @user`: Adds an Admin. Owner or Creator.
- `del admin @user`: Removes an Admin. Owner or Creator.
- `add gadmin @user`: Grants GAdmin access only in the current group. Requires
  Admin or higher.
- `del gadmin @user`: Removes the current group's GAdmin access. Requires Admin
  or higher.
- `access` or `roles`: Shows Creator, Owner, Admin, GAdmin, blacklist, ghost,
  and protection summaries.

## Reader tracking

- `lurk on`: Enables reader tracking and clears the previous reader list.
  Requires GAdmin or higher.
- `lurk off`: Disables tracking and mentions the collected readers.
- `lurk` or `readers`: Mentions the collected readers.
- `lurk names`: Shows tracking state and reader display names without mentions.
- `lurk mention`: Mentions the collected readers.

## Mentions and history

- `all`, `etiket`, or `@all`: Sends LINE's native `@All` mention. Requires
  GAdmin or higher.
- `lkick`: Mentions recently removed users and shows the actor and timestamp.
- `ljoin`: Mentions recent joins and marks accounts that joined in the same
  second.
- `history`: Lists recent join, invite, cancel, and kick events. Requires GAdmin
  or higher.
- `samejoin @user`: Shows accounts that joined in the same second as the target.

## Ghost accounts and fleet control

- `ghost 1`: Keeps one bot pending as a rescue account.
- `ghost 2`: Keeps two bots pending as rescue accounts.
- `ghost off`: Disables the pending ghost plan.
- `bye`: Makes all guard accounts leave the group. Owner or Creator only.

If no primary bot remains, an invited ghost can enter, remove blacklisted
members, and attempt to invite the primary bots again.

## Custom command names

- `setcmd kick newname`: Changes the `kick` command name. Requires Admin or
  higher.
- `setcmd kickall newname`: Changes the `kickall` command name. Requires Admin
  or higher.
- `commands`: Shows the current kick and kickall command names.

Custom command names must also be used without a leading dot.

## Settings backup

- `settings backup`: Backs up roles, custom command names, ghost settings, and
  protection state. Creator only.
- `settings restore`: Restores the most recent backup. The backup must contain
  the current Creator.

## War mode

See [WAR_COMMANDS.md](WAR_COMMANDS.md) for war levels, automatic detection,
whitelists, suspects, quarantine, and dry-run commands.

## Help

- `help` or `guard help`: Sends the role-aware command menu.
