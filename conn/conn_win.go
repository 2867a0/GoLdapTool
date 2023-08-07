//go:build windows

package conn

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"goLdapTools/cli/global"
	"goLdapTools/log"
	"strings"
)

type Connector struct {
	Conn   *ldap.Conn
	Config *global.GlobalCommand
}

func LdapConnect(globalCommand *global.GlobalCommand) (*Connector, error) {
	var conn *ldap.Conn
	var sspiConn *gssapi.SSPIClient
	var err error

	if globalCommand.GssApiLogin != "" {
		sspiConn, err = gssapi.NewSSPIClient()
		if err != nil {
			return nil, err
		}
	}

	//非加密连接
	if !globalCommand.SSLConn {
		log.PrintInfof("Trying to connecting server Ldap://%s:389", globalCommand.DomainName)
		conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:389", globalCommand.DomainName))
		if err != nil {
			return nil, err
		}
	} else {
		// SSL连接
		log.PrintInfof("Trying to connecting server Ldaps://%s:636", globalCommand.DomainName)
		conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:636", globalCommand.DomainName),
			&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, err
		}
	}

	if globalCommand.PassHash == "" && globalCommand.Password != "" {
		log.PrintInfof("Trying to binding server with password")
		log.PrintInfof("Domain Name: %s", globalCommand.DomainName)
		log.PrintInfof("username:    %s", globalCommand.UserName)
		log.PrintInfof("password:    %s", globalCommand.Password)

		err = conn.Bind(globalCommand.UserName, globalCommand.Password)
		if err != nil {
			return nil, err
		}
	} else if globalCommand.UserName != "" && globalCommand.GssApiLogin == "" {
		req := &ldap.NTLMBindRequest{
			Domain:             globalCommand.DomainName,
			Username:           strings.Split(globalCommand.UserName, "@")[0],
			Hash:               globalCommand.PassHash,
			AllowEmptyPassword: true,
			Controls:           nil,
		}

		log.PrintInfof("Trying to binding server with hash")
		log.PrintInfof("username:  %s", strings.Split(globalCommand.UserName, "@")[0])
		log.PrintInfof("pass-hash: %s", globalCommand.PassHash)

		_, err = conn.NTLMChallengeBind(req)
		if err != nil {
			return nil, err
		}
	} else {
		log.PrintInfo("Trying to binging server with current token")

		err = conn.GSSAPIBind(sspiConn, fmt.Sprintf("ldap/%s", globalCommand.GssApiLogin), "")
		if err != nil {
			return nil, err
		}
	}

	log.PrintSuccess("Binding success")

	return &Connector{Conn: conn, Config: globalCommand}, nil
}

func (conn *Connector) DoModify(dn string, control []ldap.Control, attrType string, attrVals []string) error {
	modifyReq := ldap.NewModifyRequest(dn, control)
	modifyReq.Replace(attrType, attrVals)
	return conn.Conn.Modify(modifyReq)
}
