package change

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"goLdapTools/conn"
	"goLdapTools/log"
	"goLdapTools/search"
	"goLdapTools/transform/sddl"
	"goLdapTools/transform/sddl/sid"
	"golang.org/x/text/encoding/unicode"
	"strings"
)

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
	log.PrintSuccessf("[AddUser] add user %s successful!", user)

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
	log.PrintSuccessf("change %s password to %s success!", user, password)

	// 第三步, 激活账户
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

// AddUserDAcl 添加ACL
func AddUserDAcl(conn *conn.Connector, controls []ldap.Control, user string, controlAccess string) error {
	us := search.NewPluginBase(conn.Config.BaseDN,
		fmt.Sprintf("(&(objectclass=person)(sAMAccountName=%s))", user),
		[]string{"objectSid"}, nil)
	userEntries, err := us.Search(conn, nil)
	if err != nil {
		log.PrintErrorf("search target user sid error: %s", err.Error())
		return err
	}

	userSid := ""
	for _, entry := range userEntries {
		for _, v := range entry.Attributes {
			if v.Name == "objectSid" {
				userSid = sid.SidToString(v.ByteValues[0])
			}
		}
	}
	log.PrintDebugf("get %s sid: %s", user, userSid)

	// 搜索DcSync
	property := search.NewPluginBase(conn.Config.BaseDN, "(objectClass=domain)", []string{"nTSecurityDescriptor"}, nil)
	entries, err := property.Search(conn, controls)
	if err != nil {
		log.PrintErrorf("search all user error: %s", err.Error())
		return err
	}

	// 追加SDDL
	for _, entry := range entries {
		for _, v := range entry.Attributes {
			if v.Name == "nTSecurityDescriptor" {
				// 读取原始SDDL
				sr, err := sddl.NewSecurityDescriptor(v.ByteValues[0])
				if err != nil {
					log.PrintErrorf("%s\n%s\n", "resolve nTSecurityDescriptor error:", err.Error())
					return err
				}

				dumpString := sr.DataToString(v.ByteValues[0])
				log.PrintDebugf("dump user string: %s", dumpString.String())

				// 检查原始SDDL中是否已存在带添加ACE权限
				hasPriv := false
				for _, ace := range sr.Dacl.Aces {
					// 先找到用户
					if strings.EqualFold(ace.SID.Value.(string), userSid) {
						if ace.ObjectType != nil && strings.EqualFold(controlAccess, ace.ObjectType.Value.(string)) {
							hasPriv = true
							log.PrintInfof("%s has already right", user)
						}
					}
				}

				// 创建新的Ace，将新的Ace追加到原来的SDDL数据中，整理原ADDL，转换为字节
				if !hasPriv {
					aceSize, err := sr.Dacl.AddAce(userSid, controlAccess)
					if err != nil {
						return err
					}
					if sr.OffsetOwner.Value.(uint32) != 0 {
						sr.OffsetOwner.Value = sr.OffsetOwner.Value.(uint32) + uint32(aceSize)
					}
					if sr.OffsetGroup.Value.(uint32) != 0 {
						sr.OffsetGroup.Value = sr.OffsetGroup.Value.(uint32) + uint32(aceSize)
					}
				}

				// 创建新的SDDL数据
				newRawData, err := sr.GetData()
				if err != nil {
					return err
				}

				// 调用修改
				err = conn.DoModify(conn.Config.BaseDN, controls, "nTSecurityDescriptor", []string{string(newRawData)})
				//modifyReq := ldap.NewModifyRequest(conn.Config.BaseDN, controls)
				//modifyReq.Replace("nTSecurityDescriptor", []string{string(newRawData)})
				//err = conn.Conn.Modify(modifyReq)
				if err != nil {
					return err
				}
				log.PrintSuccessf("add sddl %s success. ace id: %s", user, controlAccess)
			}
		}
	}

	return nil
}
