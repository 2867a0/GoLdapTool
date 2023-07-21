package modify

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"goLdapTools/cli/global"
	"goLdapTools/conn"
	"goLdapTools/log"
	"golang.org/x/text/encoding/unicode"
)

type UserAddConfig struct {
	AddUser   *AddUserParam
	Global    *global.GlobalCommand
	Connector *conn.Connector
}

type AddUserParam struct {
	AddUser string
	AddPass string
}

// AddUser 添加新用户
func AddUser(conn *conn.Connector, controls []ldap.Control, user string, password string) (err error) {
	// https://github.com/go-ldap/ldap/issues/106

	// 第一步，创建没密码的用户
	addReq := ldap.NewAddRequest(fmt.Sprintf("CN=%s,CN=Users,dc=test,dc=lab", user), controls)
	addReq.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user"})
	addReq.Attribute("sAMAccountName", []string{user})
	addReq.Attribute("name", []string{user})
	addReq.Attribute("userPrincipalName", []string{fmt.Sprintf("%s@test.lab", user)})

	if err := conn.Conn.Add(addReq); err != nil {
		if ldap.IsErrorWithCode(err, 68) {
			return fmt.Errorf("user %s already exist", user)
		}
		return err
	}
	log.PrintSuccessf("Add user %s successful!", user)

	// 第二步，修改用户密码
	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	pwdEncoded, err := utf16.NewEncoder().String(fmt.Sprintf("\"%s\"", password))
	if err != nil {
		return err
	}

	err = conn.DoModify(fmt.Sprintf("CN=%s,CN=Users,dc=test,dc=lab", user), nil,
		"unicodePwd", []string{pwdEncoded})
	if err != nil {
		return err
	}
	log.PrintSuccessf("change user password to %s success!", password)

	// 第三步, 激活账户 TODO 激活用户添加方式代替硬编码
	err = conn.DoModify(fmt.Sprintf("CN=%s,CN=Users,dc=test,dc=lab", user), nil, "userAccountControl", []string{"66048"})
	if err != nil {
		return err
	}
	log.PrintSuccessf("change userAccountControl to 66048 success")

	return nil
}

// 取消禁用账户的禁用状态
func ActiveUserAccount() {

}
