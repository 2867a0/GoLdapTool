package cli

import (
	"github.com/spf13/cobra"
	"goLdapTools/log"
	"goLdapTools/search"
)

var allUserCmd = &cobra.Command{
	Use:   "U",
	Short: "search all user",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, ldapConnecter := getLoginHandle(cmd)

		pau := search.NewPluginAllUser(searchCommand)

		entries, err := pau.Search(ldapConnecter)
		if err != nil {
			log.PrintErrorf("search all user error: %s", err.Error())
			return
		}
		pau.PrintResult(entries)
	},
}
