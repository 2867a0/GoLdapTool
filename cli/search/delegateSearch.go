package search

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
		searchCommand, err := getSearchHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}

		pRBCD := search.NewPluginRBCD(searchCommand)

		entries, err := pRBCD.Search(searchCommand.Connector, nil)
		if err != nil {
			log.PrintErrorf("search all user error: %s", err.Error())
			return
		}
		pRBCD.PrintResult(entries)
	},
}
