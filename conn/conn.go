package conn

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap/v3"
)

type Connector struct {
	Conn   *ldap.Conn
	Config ConnectConfig
}

func LdapConnect(config *ConnectConfig) (*Connector, error) {
	//config := ConnectConfig{
	//	Address:  "192.168.1.100:389",
	//	UserName: "administrator@test.lab",
	//	Password: "123.com",
	//	BaseDN:   "dc=test,dc=lab",
	//}
	//tlsConfig, err := getTLSconfig("192.168.1.100")
	//conn, err := ldap.DialTLS("tcp", config.Address, tlsConfig)

	var conn *ldap.Conn
	var err error

	//非加密连接
	if !config.SSLConn {
		conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:389", config.Address))
		if err != nil {
			return nil, err
		}

		err = conn.Bind(config.UserName, config.Password)
		if err != nil {
			return nil, err
		}
	} else {
		// TODO SSL连接
	}

	return &Connector{Conn: conn, Config: *config}, nil
}

func getTLSConfig(tlsName string) (tlsC *tls.Config, err error) {
	if tlsName != "" {
		tlsC = &tls.Config{
			ServerName: tlsName,
		}
		return
	}

	fmt.Println("No TLS verification enabled! ***STRONGLY*** recommend adding a trust file to the config.")
	tlsC = &tls.Config{
		InsecureSkipVerify: true,
	}
	return
}
