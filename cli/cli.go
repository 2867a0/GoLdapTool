package cli

import (
	"github.com/spf13/cobra"
	"goLdapTools/cli/global"
	"goLdapTools/cli/modify"
	"goLdapTools/cli/search"
	"goLdapTools/conn"
	"goLdapTools/log"
	"os"
)

func init() {
	//global argument
	rootCmd.PersistentFlags().StringP(global.DomainNameStr, "d", "", "domain name")
	rootCmd.PersistentFlags().StringP(global.UserStr, "u", "", "username")
	rootCmd.PersistentFlags().StringP(global.PassStr, "p", "", "password")
	rootCmd.PersistentFlags().StringP(global.BaseDnStr, "b", "", "Specify DN (ou=xx,dc=xx,dc=xx)")
	rootCmd.PersistentFlags().BoolP(global.SslStr, "s", false, "Use ssl to connect to ldap. default false")
	rootCmd.PersistentFlags().StringP(global.ExportStr, "o", "", "save result to file.")

	//search mode
	rootCmd.AddCommand(search.SearchCmd)

	//modify mode
	rootCmd.AddCommand(modify.AddCmd)
}

var rootCmd = &cobra.Command{
	Use:   "goLdapTool",
	Short: "golang ldap tool",
	Long: `An Ldap operation tool written in golang, 
with functions including searching and modifying Ldap entry attributes`,

	Run: func(cmd *cobra.Command, args []string) {
		config, err := global.ParseGlobalCommand(cmd)
		if err != nil {
			log.PrintErrorf("Parse global command error: %s", err.Error())
			os.Exit(1)
		}

		log.PrintDebugf("Connect config:\n"+
			"    server:   %s\n"+
			"    username: %s\n"+
			"    password: %s\n"+
			"    dn:       %s", config.DomainName, config.UserName, config.Password, config.BaseDN)

		// 不使用搜索模块，仅登陆
		ldapConnector, err := conn.LdapConnect(config)
		if err != nil {
			log.PrintErrorf("error: %s", err.Error())
			os.Exit(1)
		}

		log.PrintSuccessf("Connect %s successes", ldapConnector.Config.DomainName)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.PrintError(err)
		os.Exit(1)
	}
}
