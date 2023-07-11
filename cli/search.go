package cli

import (
	"github.com/spf13/cobra"
	"goLdapTools/conn"
	"goLdapTools/log"
	"goLdapTools/search"
	"os"
	"strings"
)

var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "search mode",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		//自定义搜索
		searchCommand, ldapConnecter := getLoginHandle(cmd)

		pb := search.NewPluginBase("", "", []string{}, searchCommand)
		entries, err := pb.Search(ldapConnecter, nil)
		if err != nil {
			log.PrintErrorf("custom search error: %s", err.Error())
			return
		}
		pb.PrintResult(entries)
	},
}

func getLoginHandle(cmd *cobra.Command) (*search.SearchFlag, *conn.Connector) {
	globalCommand, err := parseGlobalCommand(cmd)
	if err != nil {
		log.PrintErrorf("Parse global command error: %s", err.Error())
		os.Exit(1)
	}

	searchCommand, err := parseSearchCommand(cmd)
	if err != nil {
		log.PrintErrorf("Parse search command error: %s", err.Error())
		os.Exit(1)
	}
	if searchCommand.Dn == "" {
		searchCommand.Dn = globalCommand.BaseDN
	}

	ldapConnecter, err := conn.LdapConnect(globalCommand)
	if err != nil {
		log.PrintErrorf("ldap connect error: %s", err)
		os.Exit(1)
	}

	return searchCommand, ldapConnecter
}

func parseSearchCommand(cmd *cobra.Command) (*search.SearchFlag, error) {
	dn, err := cmd.Flags().GetString(dnStr)
	if err != nil {
		log.PrintDebugf("Failed to parse --dn-- flag %s", err)
		return nil, err
	}

	customSearch, err := cmd.Flags().GetString(customStr)
	if err != nil {
		log.PrintDebugf("Failed to parse --custom-- flag %s", err)
		return nil, err
	}

	additional, err := cmd.Flags().GetString(additionalStr)
	if err != nil {
		log.PrintDebugf("Failed to parse --additional flag %s", err)
		return nil, err
	}

	attributes := []string{}
	if additional != "" {
		for _, v := range strings.Split(additional, " ") {
			attributes = append(attributes, v)
		}
	}

	outputStr, err := cmd.Flags().GetString(exportStr)
	if err != nil {
		log.PrintDebugf("Failed to parse --output-- flag %s", err)
		return nil, err
	}

	return &search.SearchFlag{
		Dn:         dn,
		Custom:     customSearch,
		Additional: attributes,
		Exported:   outputStr,
	}, nil
}
