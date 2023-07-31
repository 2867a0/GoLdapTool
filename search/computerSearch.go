package search

type PluginAllComputers struct {
	PluginBase
}

func NewPluginAllComputers(flag *SearchConfig) PluginAllComputers {

	filter := "(objectCategory=Computer)"
	attributes := []string{"SAMAccountName", "lastLogon"}

	return PluginAllComputers{NewPluginBase(filter, attributes, flag)}
}

type PluginAllDomainController struct {
	PluginBase
}

func NewPluginAllDomainController(flag *SearchConfig) PluginAllDomainController {

	filter := "(&(objectCategory=computer)(|(primaryGroupID=521)(primaryGroupID=516)))"
	attributes := []string{"SAMAccountName", "lastLogon"}

	return PluginAllDomainController{NewPluginBase(filter, attributes, flag)}
}
