package search

import (
	"github.com/go-ldap/ldap/v3"
	"github.com/spf13/cobra"
	"goLdapTools/log"
	"goLdapTools/search"
	"goLdapTools/transform/sddl/control"
)

var allUserCmd = &cobra.Command{
	Use:   "U",
	Short: "搜索所有用户",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, err := getSearchHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}

		pau := search.NewPluginAllUser(searchCommand)

		entries, err := pau.Search(searchCommand.Connector, nil)
		if err != nil {
			log.PrintErrorf("search all user error: %s", err.Error())
			return
		}
		pau.PrintResult(entries)
	},
}

var dcsyncUserCmd = &cobra.Command{
	Use:   "DCSync",
	Short: "搜索DCSync用户",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, err := getSearchHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}

		// control value = 4 只查询dacl
		dcsyncSearch := search.NewPluginDCSyncUser(searchCommand)
		entries, err := dcsyncSearch.Search(searchCommand.Connector, []ldap.Control{&control.ControlMicrosoftSDFlags{ControlValue: 4}})
		if err != nil {
			log.PrintErrorf("Search DCSync user error: %s", err.Error())
			return
		}

		dcsyncSearch.PrintResult(entries)
	},
}

var spnUserCmd = &cobra.Command{
	Use:   "SPNU",
	Short: "查找具有SPN属性的账户",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, err := getSearchHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}

		spnUser := search.NewPluginAllSPNUser(searchCommand)

		entries, err := spnUser.Search(searchCommand.Connector, nil)
		if err != nil {
			log.PrintErrorf("search spn user error: %s", err.Error())
			return
		}
		spnUser.PrintResult(entries)
	},
}

var domainAdminUserCmd = &cobra.Command{
	Use:   "DAU",
	Short: "查找域管账户",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, err := getSearchHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}

		domainAdminUser := search.NewPluginDomainAdminUser(searchCommand)

		entries, err := domainAdminUser.Search(searchCommand.Connector, nil)
		if err != nil {
			log.PrintErrorf("search domain admin user error: %s", err.Error())
			return
		}
		domainAdminUser.PrintResult(entries)
	},
}
