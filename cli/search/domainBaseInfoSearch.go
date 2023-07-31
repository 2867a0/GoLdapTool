package search

import (
	"github.com/spf13/cobra"
	"goLdapTools/log"
	"goLdapTools/search"
)

var domainMAQCmd = &cobra.Command{
	Use:   "MAQ",
	Short: "查询域控MAQ",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, err := getSearchHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}

		maq := search.NewPluginDomainMAQ(searchCommand)

		entries, err := maq.Search(searchCommand.Connector, nil)
		if err != nil {
			log.PrintErrorf("search domain MAQ error: %s", err.Error())
			return
		}
		maq.PrintResult(entries)
	},
}
