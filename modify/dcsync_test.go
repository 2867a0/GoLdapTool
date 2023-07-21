package modify

import (
	"fmt"
	"goLdapTools/cli/global"
	"goLdapTools/conn"
	"goLdapTools/log"
	"goLdapTools/transform/sddl"
	"testing"
)

func TestUserAdd(t *testing.T) {
	log.Init(true)
	config := &global.GlobalCommand{
		DomainName: "dc.test.lab",
		UserName:   "administrator@test.lab",
		Password:   "123.com",
		BaseDN:     "dc=test,dc=lab",
		SSLConn:    true,
	}
	connect, err := conn.LdapConnect(config)
	if err != nil {
		fmt.Printf(err.Error())
		return
	}

	err = AddUser(connect, nil, "ldapTestUser7", "1234.com")
	if err != nil {
		log.PrintErrorf(err.Error())
	}
}

func TestAppendADSddl(t *testing.T) {
	log.Init(true)
	config := &global.GlobalCommand{
		DomainName: "dc.test.lab",
		UserName:   "administrator@test.lab",
		Password:   "123.com",
		BaseDN:     "dc=test,dc=lab",
		SSLConn:    false,
	}
	connect, err := conn.LdapConnect(config)
	if err != nil {
		log.PrintErrorf(err.Error())
		return
	}

	err = AppendADSddl(config, connect, nil,
		"jim", sddl.Change_PDC)
	if err != nil {
		log.PrintErrorf("add ad property DS_Replication_Get_Changes error:\n%s", err.Error())
		return
	}
}
