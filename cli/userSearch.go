package cli

import (
	"github.com/go-ldap/ldap/v3"
	"github.com/spf13/cobra"
	"goLdapTools/log"
	"goLdapTools/search"
	"goLdapTools/transform/sddl"
	"strings"
)

var allUserCmd = &cobra.Command{
	Use:   "U",
	Short: "search all user",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, ldapConnecter := getLoginHandle(cmd)

		pau := search.NewPluginAllUser(searchCommand)

		entries, err := pau.Search(ldapConnecter, nil)
		if err != nil {
			log.PrintErrorf("search all user error: %s", err.Error())
			return
		}
		pau.PrintResult(entries)
	},
}

var dcsyncUserCmd = &cobra.Command{
	Use:   "DCSync",
	Short: "search dcsync user",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		searchCommand, ldapConnecter := getLoginHandle(cmd)

		dcsyncSearch := search.NewPluginDCSyncUser(searchCommand)

		// control value = 4 只查询dacl
		entries, err := dcsyncSearch.Search(ldapConnecter,
			[]ldap.Control{&search.ControlMicrosoftSDFlags{ControlValue: 4}})
		if err != nil {
			log.PrintErrorf("search dcsync nTSecurityDescriptor error: %s", err.Error())
			return
		}

		for _, entry := range entries {
			log.PrintDebugf("resolve %s", entry.DN)

			for _, attribute := range entry.Attributes {
				if attribute.Name == "nTSecurityDescriptor" {
					sddlData, err := sddl.NewSecurityDescriptor(attribute.ByteValues[0])
					if err != nil {
						log.PrintErrorf("SDDL resolve error:\n%s", err.Error())
						return
					}

					log.PrintDebugf("dacl ace count: %d", sddlData.Dacl.Header.AceCount.Value.(uint32))
					for _, ace := range sddlData.Dacl.Aces {
						// 是5， 需要遍历
						if ace.AceType == sddl.ACCESS_ALLOWED_OBJECT_ACE_TYPE && ace.Extended.Value.(string) == "ObjectType" {
							objectTypeGuid := ace.ObjectType.Value.(string)

							//dcsync
							if strings.EqualFold(objectTypeGuid, sddl.DS_Replication_Get_Changes) || strings.EqualFold(objectTypeGuid, sddl.DS_Replication_Get_Changes_All) {
								log.PrintDebugf("Get the DCSync permission user: %s", ace.SID.Value.(string))
							}
						} else {
							// 不是5, 则是完全访问权限
						}
					}
				}
			}
		}
	},
}
