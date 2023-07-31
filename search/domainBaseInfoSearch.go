package search

type PluginDomainMAQ struct {
	PluginBase
}

func NewPluginDomainMAQ(flag *SearchConfig) PluginDomainMAQ {

	filter := "(objectClass=domain)"
	attributes := []string{"ms-DS-MachineAccountQuota"}

	return PluginDomainMAQ{NewPluginBase(filter, attributes, flag)}
}
