package change

import (
	"fmt"
	"goLdapTools/conn"
	"goLdapTools/log"
	"goLdapTools/transform/sddl"
	"testing"
)

func TestUserAdd(t *testing.T) {
	log.Init(true)
	config := &conn.ConnectConfig{
		Address:  "dc.test.lab",
		UserName: "administrator@test.lab",
		Password: "123.com",
		BaseDN:   "dc=test,dc=lab",
		SSLConn:  true,
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

func TestUserAddDacl(t *testing.T) {
	log.Init(false)
	config := &conn.ConnectConfig{
		Address:  "dc.test.lab",
		UserName: "administrator@test.lab",
		Password: "123.com",
		BaseDN:   "dc=test,dc=lab",
		SSLConn:  false,
	}
	connect, err := conn.LdapConnect(config)
	if err != nil {
		log.PrintErrorf(err.Error())
		return
	}
	err = AddUserDAcl(connect, nil,
		"john", sddl.DS_Replication_Get_Changes)
	if err != nil {
		log.PrintErrorf(err.Error())
		return
	}
}
