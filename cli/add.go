package cli

import (
	"github.com/spf13/cobra"
	"goLdapTools/conn"
	"goLdapTools/log"
	"goLdapTools/search"
	"os"
	"strings"
)

func init() {
	addCmd.AddCommand(userAddCmd)
}

var addCmd = &cobra.Command{
	Use:   "add",
	Short: "add mode",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func getAddHandle(cmd *cobra.Command) (*search.SearchFlag, *conn.Connector) {
	globalCommand, err := parseGlobalCommand(cmd)
	if err != nil {
		log.PrintErrorf("Parse global command error: %s", err.Error())
		os.Exit(1)
	}

	addCommand, err := parseAddCommand(cmd)
	if err != nil {
		log.PrintErrorf("Parse search command error: %s", err.Error())
		os.Exit(1)
	}

	ldapConnecter, err := conn.LdapConnect(globalCommand)
	if err != nil {
		log.PrintErrorf("ldap connect error: %s", err)
		os.Exit(1)
	}

	return addCommand, ldapConnecter
}

func parseAddCommand(cmd *cobra.Command) (*search.SearchFlag, error) {
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
