package cli

import (
	"github.com/go-ldap/ldap/v3"
	"github.com/spf13/cobra"
	"goLdapTools/log"
	"goLdapTools/search"
	"goLdapTools/transform/sddl/control"
)

var allUserCmd = &cobra.Command{
	Use:   "U",
	Short: "search all user",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, ldapConnecter := getSearchHandle(cmd)

		pau := search.NewPluginAllUser(searchCommand)

		entries, err := pau.Search(ldapConnecter, nil)
		if err != nil {
			log.PrintErrorf("search all user error: %s", err.Error())
			return
		}
		pau.PrintResult(entries)
	},
}

var dcsyncUserCmd = &cobra.Command{
	Use:   "DCSync",
	Short: "search dcsync user",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, ldapConnecter := getSearchHandle(cmd)

		// control value = 4 只查询dacl
		dcsyncSearch := search.NewPluginDCSyncUser(searchCommand)
		entries, err := dcsyncSearch.Search(ldapConnecter, []ldap.Control{&control.ControlMicrosoftSDFlags{ControlValue: 4}})
		if err != nil {
			log.PrintErrorf("Search DCSync user error: %s", err.Error())
			return
		}

		dcsyncSearch.PrintResult(entries)
	},
}
