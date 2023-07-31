package search

import (
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"goLdapTools/cli/global"
	"goLdapTools/conn"
	"goLdapTools/log"
	"goLdapTools/search"
	"strings"
)

const (
	CustomStr     = "custom"
	AdditionalStr = "extra"
)

func init() {
	//search mode argument
	//SearchCmd.PersistentFlags().StringP(global.DnStr, "n", "", "search dn")
	SearchCmd.Flags().StringP(CustomStr, "f", "", "Use custom search syntax")
	SearchCmd.Flags().StringP(AdditionalStr, "e", "", "Search for specified ldap attributes")

	// 计算机类搜索模块
	SearchCmd.AddCommand(domainComputerCmd)
	SearchCmd.AddCommand(domainControllerCmd)

	// 委派搜索注册
	SearchCmd.AddCommand(rbcdCmd)
	SearchCmd.AddCommand(trustedForDelegationUserCmd)
	SearchCmd.AddCommand(trustedForDelegationComputerCmd)
	SearchCmd.AddCommand(delegateUserCmd)

	// 域基本信息模块
	SearchCmd.AddCommand(domainMAQCmd)

	// 域内组信息查询
	SearchCmd.AddCommand(groupCmd)
	SearchCmd.AddCommand(adminGroupCmd)

	// 用户类搜索注册
	SearchCmd.AddCommand(allUserCmd)
	SearchCmd.AddCommand(dcsyncUserCmd)
	SearchCmd.AddCommand(spnUserCmd)
	SearchCmd.AddCommand(domainAdminUserCmd)
}

var SearchCmd = &cobra.Command{
	Use:   "search",
	Short: "search mode",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		//自定义搜索
		searchCommand, err := getSearchHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}

		pb := search.NewPluginBase("", []string{}, searchCommand)
		entries, err := pb.Search(searchCommand.Connector, nil)
		if err != nil {
			log.PrintErrorf("custom search error: %s", err.Error())
			return
		}
		pb.PrintResult(entries)
	},
}

func getSearchHandle(cmd *cobra.Command) (*search.SearchConfig, error) {
	globalCommand, err := global.ParseGlobalCommand(cmd)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Parse global command error: %s", err.Error()))
	}

	searchCommand := parseSearchCommand(cmd)
	//if err != nil {
	//	return nil, errors.New(fmt.Sprintf("Parse search command error: %s", err.Error()))
	//}

	ldapConnecter, err := conn.LdapConnect(globalCommand)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("ldap connect error: %s", err.Error()))
	}

	return &search.SearchConfig{
		Global:    globalCommand,
		Attr:      searchCommand,
		Connector: ldapConnecter,
	}, nil
}

func parseSearchCommand(cmd *cobra.Command) *search.SearchAttr {
	customSearch, _ := cmd.Flags().GetString(CustomStr)
	//if err != nil {
	//	log.PrintDebugf("Failed to parse --custom-- flag %s", err)
	//	return nil, err
	//}

	additional, _ := cmd.Flags().GetString(AdditionalStr)
	//if err != nil {
	//	log.PrintDebugf("Failed to parse --additional flag %s", err)
	//	return nil, err
	//}

	attributes := []string{}
	if additional != "" {
		for _, v := range strings.Split(additional, " ") {
			attributes = append(attributes, v)
		}
	}

	return &search.SearchAttr{
		Custom:     customSearch,
		Additional: attributes,
	}
}
