package conn

type ConnectConfig struct {
	Address  string
	UserName string
	Password string
	BaseDN   string
	SSLConn  bool
}
