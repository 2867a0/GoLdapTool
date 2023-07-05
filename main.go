package main

import (
	"goLdapTools/cli"
	"goLdapTools/log"
)

func init() {
	log.Init(log.Release)
}

func main() {
	cli.Execute()
}

//
//func (l *LDAPServer) Login(username, password string) error {
//	searchRequest := ldap.NewSearchRequest(
//		l.Config.SearchDN,
//		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
//		fmt.Sprintf("(&(objectCategory=Person)(sAMAccountName=%s))", username),
//		[]string{"dn"},
//		nil,
//	)
//	sr, err := l.Conn.Search(searchRequest)
//	if err != nil {
//		log.Errorf("[Login] search ladp err, %s", err.Error())
//		return err
//	}
//	if len(sr.Entries) != 1 {
//		log.Errorf("[Login] user does not exist or too many entries returned")
//		return fmt.Errorf("[Login] user does not exist or too many entries returned")
//	}
//	userDN := sr.Entries[0].DN
//	log.Infof("user DN, %s", userDN)
//	err = l.Conn.Bind(userDN, password)
//	if err != nil {
//		return err
//	}
//	err = l.Conn.Bind(l.Config.BindUserName, l.Config.BindPassword)
//	if err != nil {
//		return err
//	}
//	return nil
//}
//
//func (l *LDAPServer) AddUser(user, password string) (err error) {
//	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
//	pwdEncoded, _ := utf16.NewEncoder().String("\"" + password + "\"")
//	addReq := ldap.NewAddRequest(fmt.Sprintf("user=%s,%s", user, l.Config.SearchDN), []ldap.Control{})
//	addReq.Attributes("objectClass", []string{"organizationalPerson", "person", "top", "user"})
//	addReq.Attributes("sAMAccountName", []string{user})
//	addReq.Attributes("mail", []string{fmt.Sprintf("%s@XXX.com", user)})
//	addReq.Attributes("name", []string{user})
//	addReq.Attributes("userAccountControl", []string{fmt.Sprintf("%d", 66048)})
//	addReq.Attributes("unicodePwd", []string{pwdEncoded})
//	if err := l.Conn.Add(addReq); err != nil {
//		if ldap.IsErrorWithCode(err, 68) {
//			return fmt.Errorf("user %s already exist", user)
//		}
//		return err
//	}
//	log.Infof("[AddUser] add user %s successful!", user)
//	return nil
//}
//
//func (l *LDAPServer) ResetPassword(user, password string) error {
//	utf16 := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
//	pwdEncoded, _ := utf16.NewEncoder().String("\"" + password + "\"")
//	modReq := ldap.NewModifyRequest(fmt.Sprintf("user=%s,%s", user, l.Config.SearchDN), []ldap.Control{})
//	modReq.Replace("unicodePwd", []string{pwdEncoded})
//	modReq.Replace("userAccountControl", []string{fmt.Sprintf("%d", 66048)})
//	if err := l.Conn.Modify(modReq); err != nil {
//		log.Errorf("[ResetPassword] %s reset password Failed!", user)
//		return err
//	}
//	log.Infof("[ResetPassword] %s reset password successful!", user)
//	return nil
//}
//
//func (l *LDAPServer) DeleteUser(user string) (err error) {
//	delReq := ldap.NewDelRequest(fmt.Sprintf("user=%s,%s", user, l.Config.SearchDN), []ldap.Control{})
//	if err := l.Conn.Del(delReq); err != nil {
//		log.Errorf("[DeleteUser] delete user  %s  failed!", user)
//		return err
//	}
//	log.Infof("[DeleteUser] delete user  %s  successful!", user)
//	return nil
//}
//
//func (l *LDAPServer) GetAllUser() ([]*ldap.Entry, error) {
//
//}
