package modify

import (
	"github.com/spf13/cobra"
	"goLdapTools/cli/global"
	"goLdapTools/conn"
	"goLdapTools/log"
	"goLdapTools/modify"
)

const (
	usernameStr = "add-user"
	passwordStr = "add-pass"
)

func init() {
	userAddCmd.Flags().StringP(usernameStr, "", "", "username to add")
	userAddCmd.Flags().StringP(passwordStr, "", "", "password")
}

var userAddCmd = &cobra.Command{
	Use:   "user",
	Short: "add user",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		userAddConfig, err := getUserAddHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}
		if !userAddConfig.Global.SSLConn {
			log.PrintErrorf("Adding user operations requires the --ssl parameter")
			return
		}

		err = modify.AddUser(userAddConfig.Connector, nil, userAddConfig.AddUser.AddUser, userAddConfig.AddUser.AddPass)
		if err != nil {
			log.PrintErrorf("Add user error:\n%s", err.Error())
			return
		}
	},
}

func getUserAddHandle(cmd *cobra.Command) (*modify.UserAddConfig, error) {
	globalCommand, err := global.ParseGlobalCommand(cmd)
	if err != nil {
		log.PrintErrorf("Parse global command error: %s", err.Error())
		return nil, err
	}

	username, err := cmd.Flags().GetString(usernameStr)
	if err != nil {
		log.PrintErrorf("Parse username command error: %s", err.Error())
		return nil, err
	}

	password, err := cmd.Flags().GetString(passwordStr)
	if err != nil {
		log.PrintErrorf("Parse password command error: %s", err.Error())
		return nil, err
	}

	ldapConnecter, err := conn.LdapConnect(globalCommand)
	if err != nil {
		log.PrintErrorf("ldap connect error: %s", err)
		return nil, err
	}

	return &modify.UserAddConfig{
		AddUser: &modify.AddUserParam{
			AddUser: username,
			AddPass: password,
		},
		Global:    globalCommand,
		Connector: ldapConnecter,
	}, nil
}
