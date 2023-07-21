package modify

import (
	"github.com/spf13/cobra"
	"goLdapTools/cli/global"
	"goLdapTools/conn"
	"goLdapTools/log"
	"goLdapTools/modify"
	"goLdapTools/transform/sddl"
)

const (
	targetUsername = "target-user"
)

func init() {
	dcsyncCmd.Flags().StringP(targetUsername, "t", "", "target user to add")
}

var dcsyncCmd = &cobra.Command{
	Use:   "dcsync",
	Short: "add dcsync property",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		udcsyncConfig, err := getDcSyncHandle(cmd)
		if err != nil {
			log.PrintError(err.Error())
			return
		}

		err = modify.AppendADSddl(udcsyncConfig.Global, udcsyncConfig.Connector, nil,
			udcsyncConfig.Target, sddl.DS_Replication_Get_Changes)
		if err != nil {
			log.PrintErrorf("add ad property DS_Replication_Get_Changes error:\n%s", err.Error())
			return
		}

		err = modify.AppendADSddl(udcsyncConfig.Global, udcsyncConfig.Connector, nil,
			udcsyncConfig.Target, sddl.DS_Replication_Get_Changes_All)
		if err != nil {
			log.PrintErrorf("add ad property DS_Replication_Get_Changes_All error:\n%s", err.Error())
			return
		}
	},
}

func getDcSyncHandle(cmd *cobra.Command) (*modify.DcSyncAddConfig, error) {
	globalConfig, err := global.ParseGlobalCommand(cmd)
	if err != nil {
		return nil, err
	}

	targetUserNameParam, err := cmd.Flags().GetString(targetUsername)
	if err != nil {
		return nil, err
	}

	ldapConnecter, err := conn.LdapConnect(globalConfig)
	if err != nil {
		return nil, err
	}

	return &modify.DcSyncAddConfig{
		Target:    targetUserNameParam,
		Global:    globalConfig,
		Connector: ldapConnecter,
	}, nil
}
