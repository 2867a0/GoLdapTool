package search

type PluginAllUser struct {
	PluginBase
}

func NewPluginAllUser(flag *SearchFlag) PluginAllUser {

	filter := "(objectclass=user)"
	attributes := []string{"SAMAccountName", "lastLogon"}

	return PluginAllUser{NewPluginBase("", filter, attributes, flag)}
}

type PluginDCSyncUser struct {
	PluginBase
}

func NewPluginDCSyncUser(flag *SearchFlag) PluginDCSyncUser {
	filter := "(objectClass=domain)"
	attributes := []string{"nTSecurityDescriptor"}

	return PluginDCSyncUser{NewPluginBase("", filter, attributes, flag)}
}

//func (au *PluginAllUser) Search(conn *conn.Connector) ([]*ldap.Entry, error) {
//searchRequest := ldap.NewSearchRequest(
//	au.BaseDN,
//	ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
//	au.Filter,
//	au.Attributes,
//	nil,
//)
//sr, err := conn.Conn.Search(searchRequest)
//if err != nil {
//	log.PrintErrorf("search ldap error: %s", err.Error())
//	return nil, err
//}
//
//return sr.Entries, nil
//}
