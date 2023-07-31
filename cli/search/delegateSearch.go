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

var trustedForDelegationUserCmd = &cobra.Command{
	Use:   "TDU",
	Short: "查找非约束委派用户",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, err := getSearchHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}

		tdu := search.NewPluginTrustedForDelegationUser(searchCommand)

		entries, err := tdu.Search(searchCommand.Connector, nil)
		if err != nil {
			log.PrintErrorf("search trusted for delegation user error: %s", err.Error())
			return
		}
		tdu.PrintResult(entries)
	},
}

var trustedForDelegationComputerCmd = &cobra.Command{
	Use:   "TDM",
	Short: "查找非约束委派机器",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, err := getSearchHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}

		tdm := search.NewPluginTrustedForDelegationComputer(searchCommand)

		entries, err := tdm.Search(searchCommand.Connector, nil)
		if err != nil {
			log.PrintErrorf("search trusted for delegation computer error: %s", err.Error())
			return
		}
		tdm.PrintResult(entries)
	},
}

var delegateUserCmd = &cobra.Command{
	Use:   "D",
	Short: "查询约束委派用户",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, err := getSearchHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}

		delegateUser := search.NewPluginDelegateUser(searchCommand)

		entries, err := delegateUser.Search(searchCommand.Connector, nil)
		if err != nil {
			log.PrintErrorf("search delegate user error: %s", err.Error())
			return
		}
		delegateUser.PrintResult(entries)
	},
}
