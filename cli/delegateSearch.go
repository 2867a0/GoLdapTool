package cli

import (
	"github.com/spf13/cobra"
	"goLdapTools/log"
	"goLdapTools/search"
)

var rbcdCmd = &cobra.Command{
	Use:   "RBCD",
	Short: "search rbcd",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, ldapConnecter := getLoginHandle(cmd)

		pRBCD := search.NewPluginRBCD(searchCommand)

		entries, err := pRBCD.Search(ldapConnecter)
		if err != nil {
			log.PrintErrorf("search all user error: %s", err.Error())
			return
		}
		pRBCD.PrintResult(entries)
	},
}
