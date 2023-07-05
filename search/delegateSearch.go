package search

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"goLdapTools/conn"
	"goLdapTools/log"
	"goLdapTools/transform"
)

type PluginRBCD struct {
	PluginBase
}

func NewPluginRBCD(flag *SearchFlag) PluginRBCD {

	filter := "(objectCategory=Computer)"
	attributes := []string{"msDS-AllowedToActOnBehalfOfOtherIdentity", "mS-DS-CreatorSID"}

	return PluginRBCD{NewPluginBase("", filter, attributes, flag)}
}

func (pluginRBCD *PluginRBCD) Search(conn *conn.Connector) ([]*ldap.Entry, error) {
	var results []*ldap.Entry

	firstSearch, err := pluginRBCD.PluginBase.Search(conn)
	if err != nil {
		return nil, err
	}

	for _, entry := range firstSearch {
		if len(entry.Attributes) == 0 {
			continue
		}

		for _, attribute := range entry.Attributes {
			if attribute.Name == "mS-DS-CreatorSID" {
				sidString := transform.SidToString(entry.GetRawAttributeValue("mS-DS-CreatorSID"))
				log.PrintDebugf("get sid: %s", sidString)

				pluginRBCD.Filter = fmt.Sprintf("(&(objectCategory=person)(objectSid=%s))", sidString)
				pluginRBCD.Attributes = []string{"distinguishedName"}

				secondSearch, err := pluginRBCD.PluginBase.Search(conn)
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
