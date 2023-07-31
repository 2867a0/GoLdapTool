package search

type PluginGroups struct {
	PluginBase
}

func NewPluginGroups(flag *SearchConfig) PluginGroups {

	filter := "(objectCategory=group)"
	attributes := []string{"distinguishedName"}

	return PluginGroups{NewPluginBase(filter, attributes, flag)}
}

type PluginAdminGroups struct {
	PluginBase
}

func NewPluginAdminGroups(flag *SearchConfig) PluginAdminGroups {

	filter := "(&(objectCategory=group)(adminCount=1))"
	attributes := []string{"distinguishedName"}

	return PluginAdminGroups{NewPluginBase(filter, attributes, flag)}
}
