package modify

import (
	"github.com/spf13/cobra"
)

func init() {

	// 添加用户
	AddCmd.AddCommand(userAddCmd)

	// 添加dcsync权限
	AddCmd.AddCommand(dcsyncCmd)
}

var AddCmd = &cobra.Command{
	Use:   "add",
	Short: "add mode",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {

	},
}
