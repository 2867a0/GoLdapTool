package search

import (
	"github.com/spf13/cobra"
	"goLdapTools/log"
	"goLdapTools/search"
)

var domainComputerCmd = &cobra.Command{
	Use:   "C",
	Short: "查找域机器",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, err := getSearchHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}

		allComputers := search.NewPluginAllComputers(searchCommand)

		entries, err := allComputers.Search(searchCommand.Connector, nil)
		if err != nil {
			log.PrintErrorf("search all computers error: %s", err.Error())
			return
		}
		allComputers.PrintResult(entries)
	},
}

var domainControllerCmd = &cobra.Command{
	Use:   "DC",
	Short: "查找域控",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, err := getSearchHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}

		dc := search.NewPluginAllDomainController(searchCommand)

		entries, err := dc.Search(searchCommand.Connector, nil)
		if err != nil {
			log.PrintErrorf("search all domain controllers error: %s", err.Error())
			return
		}
		dc.PrintResult(entries)
	},
}
