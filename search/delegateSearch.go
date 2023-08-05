package search

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"goLdapTools/conn"
	"goLdapTools/log"
	"goLdapTools/transform/sddl/sid"
)

type PluginRBCD struct {
	PluginBase
}

func NewPluginRBCD(flag *SearchConfig) PluginRBCD {

	filter := "(objectCategory=Computer)"
	attributes := []string{"msDS-AllowedToActOnBehalfOfOtherIdentity", "mS-DS-CreatorSID"}

	return PluginRBCD{NewPluginBase(filter, attributes, flag)}
}

func (pluginRBCD *PluginRBCD) Search(conn *conn.Connector, controls []ldap.Control) ([]*ldap.Entry, error) {
	var results []*ldap.Entry

	firstSearch, err := pluginRBCD.PluginBase.Search(conn, controls)
	if err != nil {
		return nil, err
	}

	for _, entry := range firstSearch {
		if len(entry.Attributes) == 0 {
			continue
		}

		for _, attribute := range entry.Attributes {
			if attribute.Name == "mS-DS-CreatorSID" {
				sidString, _ := sid.SidToString(entry.GetRawAttributeValue("mS-DS-CreatorSID"))
				log.PrintDebugf("get sid: %s", sidString)

				pluginRBCD.Filter = fmt.Sprintf("(&(objectCategory=person)(objectSid=%s))", sidString)
				pluginRBCD.Attributes = []string{"distinguishedName"}

				secondSearch, err := pluginRBCD.PluginBase.Search(conn, controls)
				if err != nil {
					log.PrintDebug("second search error")
					return nil, err
				}

				msDS_AllowedToActOnBehalfOfOtherIdentity := ""
				for _, a := range entry.Attributes {
					if a.Name == "msDS-AllowedToActOnBehalfOfOtherIdentity" {
						msDS_AllowedToActOnBehalfOfOtherIdentity = a.Name
					}
				}

				results = append(results, &ldap.Entry{
					DN: entry.DN,
					Attributes: []*ldap.EntryAttribute{
						{
							Name:   "mS-DS-CreatorSID",
							Values: []string{secondSearch[0].DN},
						},
						{
							Name:   "msDS-AllowedToActOnBehalfOfOtherIdentity",
							Values: []string{msDS_AllowedToActOnBehalfOfOtherIdentity},
						},
					},
				})
			}
		}
	}
	return results, nil
}

type PluginTrustedForDelegationUser struct {
	PluginBase
}

func NewPluginTrustedForDelegationUser(flag *SearchConfig) PluginTrustedForDelegationUser {

	filter := "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
	attributes := []string{"distinguishedName"}

	return PluginTrustedForDelegationUser{NewPluginBase(filter, attributes, flag)}
}

type PluginTrustedForDelegationComputer struct {
	PluginBase
}

func NewPluginTrustedForDelegationComputer(flag *SearchConfig) PluginTrustedForDelegationComputer {

	filter := "(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
	attributes := []string{"distinguishedName"}

	return PluginTrustedForDelegationComputer{NewPluginBase(filter, attributes, flag)}
}

type PluginDelegateUser struct {
	PluginBase
}

func NewPluginDelegateUser(flag *SearchConfig) PluginDelegateUser {

	filter := "(&(samAccountType=805306368)(msds-allowedtodelegateto=*))"
	attributes := []string{"msds-allowedtodelegateto"}

	return PluginDelegateUser{NewPluginBase(filter, attributes, flag)}
}
