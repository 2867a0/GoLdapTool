package search

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"goLdapTools/conn"
	"goLdapTools/log"
	"goLdapTools/transform/sddl"
	"goLdapTools/transform/sddl/ace"
	"strings"
)

type PluginAllUser struct {
	PluginBase
}

func NewPluginAllUser(flag *SearchConfig) PluginAllUser {

	filter := "(objectclass=user)"
	attributes := []string{"SAMAccountName", "lastLogon"}

	return PluginAllUser{NewPluginBase(filter, attributes, flag)}
}

type PluginDCSyncUser struct {
	PluginBase
}

func NewPluginDCSyncUser(flag *SearchConfig) PluginDCSyncUser {
	filter := "(objectClass=domain)"
	attributes := []string{"nTSecurityDescriptor"}

	return PluginDCSyncUser{NewPluginBase(filter, attributes, flag)}
}
func (pluginDcSync *PluginDCSyncUser) Search(conn *conn.Connector, controls []ldap.Control) ([]*ldap.Entry, error) {
	var results []*ldap.Entry

	entries, err := pluginDcSync.PluginBase.Search(conn, controls)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		log.PrintDebugf("Resolve %s", entry.DN)

		for _, attribute := range entry.Attributes {
			if attribute.Name != "nTSecurityDescriptor" {
				continue
			}

			sddlData, err := sddl.NewSecurityDescriptor(attribute.ByteValues[0])
			if err != nil {
				return nil, err
			}

			log.PrintSuccessf("Get dacl aceEntry count: %d", sddlData.Dacl.AceCount.Value.(uint16))

			dcsyncUserMap := make(map[string]string)
			for _, aceEntry := range sddlData.Dacl.Aces {

				// 跳过没用的sid
				if len(strings.Split(aceEntry.SID.Value.(string), "-")) <= 5 {
					continue
				}

				// 是5， 需要遍历
				if aceEntry.AceType == ace.ACCESS_ALLOWED_OBJECT_ACE_TYPE && aceEntry.Extended.Value.(string) == "ObjectType" {
					objectTypeGuid := aceEntry.ObjectType.Value.(string)

					//dcsync
					if strings.EqualFold(objectTypeGuid, sddl.DS_Replication_Get_Changes) ||
						strings.EqualFold(objectTypeGuid, sddl.DS_Replication_Get_Changes_All) {
						log.PrintDebugf("Get the DCSync permission user: %s", aceEntry.SID.Value.(string))

						dcsyncUserMap[aceEntry.SID.Value.(string)] = ""
					}
				} else {
					// 不是5, 则是完全访问权限
					log.PrintDebugf("Get a full access account %s", aceEntry.SID.Value.(string))
					dcsyncUserMap[aceEntry.SID.Value.(string)] = ""
				}
			}

			for key := range dcsyncUserMap {
				pluginDcSync.Filter = fmt.Sprintf("(objectSid=%s)", key)
				pluginDcSync.Attributes = []string{"distinguishedName"}
				userString, err := pluginDcSync.PluginBase.Search(conn, nil)
				if err != nil {
					return nil, err
				}

				results = append(results, &ldap.Entry{
					DN: entry.DN,
					Attributes: []*ldap.EntryAttribute{
						{
							Name:   "User           ",
							Values: []string{userString[0].DN},
						},
						{
							Name:   "DCSync-User-SID",
							Values: []string{key},
						},
					},
				})
			}

		}
	}

	return results, nil
}

type PluginAllSPNUser struct {
	PluginBase
}

func NewPluginAllSPNUser(flag *SearchConfig) PluginAllSPNUser {

	filter := "(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol=524288))(serviceprincipalname=*/*))"
	attributes := []string{"distinguishedName", "servicePrincipalName"}

	return PluginAllSPNUser{NewPluginBase(filter, attributes, flag)}
}

type PluginDomainAdminUser struct {
	PluginBase
}

func NewPluginDomainAdminUser(flag *SearchConfig) PluginDomainAdminUser {

	filter := "(&(|(&(objectCategory=person)(objectClass=user)))(adminCount=1))"
	attributes := []string{"distinguishedName"}

	return PluginDomainAdminUser{NewPluginBase(filter, attributes, flag)}
}
