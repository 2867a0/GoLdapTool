package search

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"goLdapTools/cli/global"
	"goLdapTools/conn"
	"goLdapTools/log"
	"goLdapTools/transform/sddl"
	"strings"
)

type SearchConfig struct {
	Global    *global.GlobalCommand
	Attr      *SearchAttr
	Connector *conn.Connector
}

// SearchAttr 搜索条目参数结构体
type SearchAttr struct {
	// filter
	Custom string
	// attribute
	Additional []string
}

type SearchInterface interface {
	Search(conn *conn.Connector, controls []ldap.Control) ([]*ldap.Entry, error)
	PrintResult(entries []*ldap.Entry)
}

// PluginBase 搜索函数父类
type PluginBase struct {
	BaseDN     string
	Filter     string
	Attributes []string
}

// NewPluginBase 父类默认初始化搜索参数
func NewPluginBase(defaultFilter string, defaultAttribute []string, flag *SearchConfig) PluginBase {
	// 更新属性
	if flag.Attr != nil {
		if flag.Attr.Custom != "" {
			defaultFilter = flag.Attr.Custom
		}

		if len(flag.Attr.Additional) != 0 {
			defaultAttribute = append(defaultAttribute, flag.Attr.Additional...)
		}
	}

	// 过滤重复元素
	attributes := removeDuplicate(defaultAttribute)

	return PluginBase{
		BaseDN:     flag.Global.BaseDN,
		Filter:     defaultFilter,
		Attributes: attributes,
	}
}

// Search 父类默认搜索方法
func (pluginBase *PluginBase) Search(conn *conn.Connector, controls []ldap.Control) ([]*ldap.Entry, error) {
	log.PrintInfof("Search info:\n"+
		"    base dn:   %s\n"+
		"    filter:    %s\n"+
		"    attribute: %s\n", pluginBase.BaseDN, pluginBase.Filter, pluginBase.Attributes)

	searchRequest := ldap.NewSearchRequest(
		pluginBase.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		pluginBase.Filter,
		pluginBase.Attributes,
		controls,
	)
	sr, err := conn.Conn.Search(searchRequest)
	if err != nil {
		log.PrintErrorf("search ldap error: %s", err.Error())
		return nil, err
	}

	return sr.Entries, nil
}

// PrintResult 父类默认打印结果函数
func (pluginBase PluginBase) PrintResult(entries []*ldap.Entry) {
	var result strings.Builder
	for _, entry := range entries {
		result.WriteString(fmt.Sprintf("%s\n", entry.DN))

		for _, v := range entry.Attributes {
			if v.Name == "nTSecurityDescriptor" {
				sr, err := sddl.NewSecurityDescriptor(v.ByteValues[0])
				if err != nil {
					log.PrintErrorf("%s\n%s\n", "resolve nTSecurityDescriptor error:", err.Error())
					return
				}
				resultStrings := sr.DataToString(v.ByteValues[0])
				log.PrintDebugf("dump nTSecurityDescriptor string: \n%s\n", resultStrings.String())
			} else {
				result.WriteString(fmt.Sprintf("    %s: %s\n", v.Name, strings.Join(v.Values, " ")))
			}
		}
	}
	log.PrintSuccessf("%s\n%s", "Search result:", result.String())
	log.PrintSuccessf("result count: %d\n", len(entries))
}

// 通过map主键唯一的特性过滤重复元素
func removeDuplicate(arr []string) []string {
	resArr := make([]string, 0)
	tmpMap := make(map[string]interface{})
	for _, val := range arr {
		//判断主键为val的map是否存在
		if _, ok := tmpMap[val]; !ok {
			resArr = append(resArr, val)
			tmpMap[val] = nil
		}
	}

	return resArr
}
