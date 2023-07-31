package search

import (
	"github.com/spf13/cobra"
	"goLdapTools/log"
	"goLdapTools/search"
)

var groupCmd = &cobra.Command{
	Use:   "GROUP",
	Short: "域内所有的组",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, err := getSearchHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}

		group := search.NewPluginGroups(searchCommand)

		entries, err := group.Search(searchCommand.Connector, nil)
		if err != nil {
			log.PrintErrorf("search domain group error: %s", err.Error())
			return
		}
		group.PrintResult(entries)
	},
}

var adminGroupCmd = &cobra.Command{
	Use:   "AGROUP",
	Short: "查询域管组",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, err := getSearchHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}

		adminGroups := search.NewPluginAdminGroups(searchCommand)

		entries, err := adminGroups.Search(searchCommand.Connector, nil)
		if err != nil {
			log.PrintErrorf("search domain admin group error: %s", err.Error())
			return
		}
		adminGroups.PrintResult(entries)
	},
}
