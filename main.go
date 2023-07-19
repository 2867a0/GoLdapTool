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
