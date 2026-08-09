package guard

import (
	"fmt"
	"strings"
)

func helpMenu(role Role) string {
	lines := []string{
		fmt.Sprintf("HELP MENU • %s", strings.ToUpper(role.String())),
		"──── COMMON ────",
		"access | commands | protect status | leader",
	}
	if role >= RoleGAdmin {
		lines = append(lines,
			"──── GADMIN ────",
			"status | bots | lkick | ljoin",
			"history | samejoin @",
			"lurk on/off | lurk | readers | lurk names",
			"all | @all",
			"kick @ | invite @ | unban @",
		)
	}
	if role >= RoleAdmin {
		lines = append(lines,
			"──── ADMIN ────",
			"protect on/off | protect status",
			"invite/cancel/kick protect on/off",
			"qr/all/flood protect on/off",
			"bot health | kickall",
			"blacklist @ | unban @ | clear blacklist",
			"ghost 1/2/off | add/del gadmin @",
			"setcmd kick <name> | setcmd kickall <name>",
		)
	}
	if role >= RoleOwner {
		lines = append(lines,
			"──── OWNER ────",
			"war on 5m | war off | war status",
			"war dashboard | war report | war level 1/2",
			"war lock/unlock | war auto on/off",
			"war sensitivity low/medium/high | war cooldown 2m",
			"war whitelist add/del @ | war suspects",
			"war quarantine @ | war pardon @",
			"war dryrun on/off | war clear",
			"add me | ticket | add/del admin @ | bye",
		)
	}
	if role >= RoleCreator {
		lines = append(lines,
			"──── CREATOR ────",
			"war level 3",
			"add/del creator @ | add/del owner @",
			"settings backup | settings restore",
		)
	}
	return strings.Join(lines, "\n")
}
