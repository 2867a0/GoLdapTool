package cli

import (
	"github.com/spf13/cobra"
	"goLdapTools/change"
	"goLdapTools/conn"
	"goLdapTools/log"
	"os"
)

const (
	usernameStr = "add-user"
	passwordStr = "add-pass"
)

type addCmdFlag struct {
	username string
	password string
}

func init() {
	userAddCmd.Flags().StringP(usernameStr, "", "", "username to add")
	userAddCmd.Flags().StringP(passwordStr, "", "", "password")
}

var userAddCmd = &cobra.Command{
	Use:   "user",
	Short: "add user",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		command, conn := getUserAddHandle(cmd)
		err := change.AddUser(conn, nil, command.username, command.password)
		if err != nil {
			log.PrintErrorf("Add user error:\n%s", err.Error())
			os.Exit(-1)
		}
	},
}

func getUserAddHandle(cmd *cobra.Command) (*addCmdFlag, *conn.Connector) {
	globalCommand, err := parseGlobalCommand(cmd)
	if err != nil {
		log.PrintErrorf("Parse global command error: %s", err.Error())
		os.Exit(1)
	}

	username, err := cmd.Flags().GetString(usernameStr)
	if err != nil {
		log.PrintErrorf("Parse username command error: %s", err.Error())
		os.Exit(1)
	}

	password, err := cmd.Flags().GetString(passwordStr)
	if err != nil {
		log.PrintErrorf("Parse password command error: %s", err.Error())
		os.Exit(1)
	}

	ldapConnecter, err := conn.LdapConnect(globalCommand)
	if err != nil {
		log.PrintErrorf("ldap connect error: %s", err)
		os.Exit(1)
	}

	return &addCmdFlag{
		username: username,
		password: password,
	}, ldapConnecter
}
