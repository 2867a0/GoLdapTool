package conn

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"goLdapTools/cli/global"
	"goLdapTools/log"
)

type Connector struct {
	Conn   *ldap.Conn
	Config *global.GlobalCommand
}

func LdapConnect(globalCommand *global.GlobalCommand) (*Connector, error) {
	var conn *ldap.Conn
	var err error

	//非加密连接
	if !globalCommand.SSLConn {
		log.PrintDebugf("Trying to connecting server Ldap://%s:389", globalCommand.DomainName)
		conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:389", globalCommand.DomainName))
		if err != nil {
			return nil, err
		}
	} else {
		// SSL连接
		log.PrintDebugf("Trying to connecting server Ldaps://%s:636", globalCommand.DomainName)
		conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:636", globalCommand.DomainName),
			&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, err
		}
	}

	log.PrintDebugf("Trying to binding server")
	err = conn.Bind(globalCommand.UserName, globalCommand.Password)
	if err != nil {
		return nil, err
	}

	log.PrintSuccess("Binding success")

	return &Connector{Conn: conn, Config: globalCommand}, nil
}

func (conn *Connector) DoModify(dn string, control []ldap.Control, attrType string, attrVals []string) error {
	modifyReq := ldap.NewModifyRequest(dn, control)
	modifyReq.Replace(attrType, attrVals)
	return conn.Conn.Modify(modifyReq)
}
