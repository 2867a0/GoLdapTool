package cli

import (
	"errors"
	"fmt"
	"goLdapTools/conn"
	"goLdapTools/log"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

const (
	domainNameStr = "domain-name"
	userStr       = "username"
	passwordStr   = "password"
	baseDnStr     = "base-dn"
	sslStr        = "ssl"

	dnStr         = "dn"
	customStr     = "custom"
	additionalStr = "extra"
	exportStr     = "export"
)

func init() {
	//global argument
	rootCmd.PersistentFlags().StringP(domainNameStr, "d", "", "domain name")
	rootCmd.PersistentFlags().StringP(userStr, "u", "", "username")
	rootCmd.PersistentFlags().StringP(passwordStr, "p", "", "password")
	rootCmd.PersistentFlags().StringP(baseDnStr, "b", "", "Specify DN (ou=xx,dc=xx,dc=xx)")
	rootCmd.PersistentFlags().BoolP(sslStr, "s", false, "Use ssl to connect to ldap. default false")

	//search mode argument
	searchCmd.PersistentFlags().StringP(dnStr, "n", "", "search dn")
	searchCmd.PersistentFlags().StringP(customStr, "f", "", "Use custom search syntax")
	searchCmd.PersistentFlags().StringP(additionalStr, "a", "", "Search for specified ldap attributes")
	searchCmd.PersistentFlags().StringP(exportStr, "o", "", "save result to file.")
	rootCmd.AddCommand(searchCmd)

	// 委派搜索注册
	searchCmd.AddCommand(rbcdCmd)

	// 用户类搜索注册
	searchCmd.AddCommand(allUserCmd)
	searchCmd.AddCommand(dcsyncUserCmd)
}

var rootCmd = &cobra.Command{
	Use:   "goLdapTool",
	Short: "golang ldap tool",
	Long: `An Ldap operation tool written in golang, 
with functions including searching and modifying Ldap entry attributes`,

	Run: func(cmd *cobra.Command, args []string) {
		config, err := parseGlobalCommand(cmd)
		if err != nil {
			log.PrintErrorf("Parse global command error: %s", err.Error())
			os.Exit(1)
		}

		log.PrintDebugf("Connect config:\n"+
			"    server:   %s\n"+
			"    username: %s\n"+
			"    password: %s\n"+
			"    dn:       %s", config.Address, config.UserName, config.Password, config.BaseDN)

		// 不使用搜索模块，仅登陆
		ldapConnecter, err := conn.LdapConnect(config)
		if err != nil {
			log.PrintErrorf("error: %s", err.Error())
			os.Exit(1)
		}

		log.PrintSuccessf("Connect %s successes", ldapConnecter.Config.Address)

	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.PrintError(err)
		os.Exit(1)
	}
}

func parseGlobalCommand(cmd *cobra.Command) (config *conn.ConnectConfig, err error) {
	domainName, err := cmd.Flags().GetString(domainNameStr)
	if err != nil {
		log.PrintDebugf("Failed to parse --domainName-- flag %s", err)
		return nil, err
	}
	if domainName == "" {
		return nil, errors.New("domain name is not specified")
	}

	u, err := cmd.Flags().GetString(userStr)
	if err != nil {
		log.PrintDebugf("Failed to parse --username-- flag %s", err)
		return nil, err
	}

	password, err := cmd.Flags().GetString(passwordStr)
	if err != nil {
		log.PrintDebugf("Failed to parse --password-- flag %s", err)
		return nil, err
	}

	domainNameArr := strings.Split(domainName, ".")
	baseDN, err := cmd.Flags().GetString(baseDnStr)
	if err != nil {
		log.PrintDebugf("Failed to parse --base dn-- flag %s", err)
		return nil, err
	}
	if baseDN == "" {
		baseDN = fmt.Sprintf("dc=%s,dc=%s", domainNameArr[len(domainNameArr)-2], domainNameArr[len(domainNameArr)-1])
	}

	ssl, err := cmd.Flags().GetBool(sslStr)
	if err != nil {
		log.PrintErrorf("Failed to parse --ssl-- flag %s", err)
		return nil, err
	}

	userName := fmt.Sprintf("%s@%s.%s", u, domainNameArr[len(domainNameArr)-2], domainNameArr[len(domainNameArr)-1])
	return &conn.ConnectConfig{
		Address:  domainName,
		UserName: userName,
		Password: password,
		BaseDN:   baseDN,
		SSLConn:  ssl,
	}, nil
}
