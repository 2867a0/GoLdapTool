//go:build !windows

package global

import (
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"goLdapTools/log"
	"strings"
)

const (
	DomainNameStr = "domain-name"
	UserStr       = "username"
	PassStr       = "password"
	HashStr       = "hash"
	BaseDnStr     = "base-dn"
	SslStr        = "ssl"
	ExportStr     = "output"
)

type GlobalCommand struct {
	DomainName string
	UserName   string
	Password   string
	PassHash   string
	BaseDN     string
	SSLConn    bool
	Export     string
}

func ParseGlobalCommand(cmd *cobra.Command) (config *GlobalCommand, err error) {
	domainName, err := cmd.Flags().GetString(DomainNameStr)
	if err != nil {
		log.PrintDebugf("Failed to parse --domainName-- flag %s", err)
		return nil, err
	}
	if domainName == "" {
		return nil, errors.New("domain name is not specified")
	}

	u, err := cmd.Flags().GetString(UserStr)
	if err != nil {
		log.PrintDebugf("Failed to parse --username-- flag %s", err)
		return nil, err
	}

	password, err := cmd.Flags().GetString(PassStr)
	if err != nil {
		log.PrintDebugf("Failed to parse --password-- flag %s", err)
		return nil, err
	}

	passHash, err := cmd.Flags().GetString(HashStr)
	if err != nil {
		log.PrintDebugf("Failed to parse --hash-- flag %s", err)
		return nil, err
	}

	domainNameArr := strings.Split(domainName, ".")
	baseDN, err := cmd.Flags().GetString(BaseDnStr)
	if err != nil {
		log.PrintDebugf("Failed to parse --base dn-- flag %s", err)
		return nil, err
	}
	if baseDN == "" {
		baseDN = fmt.Sprintf("dc=%s", strings.Join(domainNameArr, ",dc="))
	}

	ssl, err := cmd.Flags().GetBool(SslStr)
	if err != nil {
		log.PrintErrorf("Failed to parse --ssl-- flag %s", err)
		return nil, err
	}

	export, err := cmd.Flags().GetString(ExportStr)
	if err != nil {
		log.PrintErrorf("Failed to parse --export-- flag %s", err)
		return nil, err
	}

	log.SaveResultStr = export

	var userName = u
	if !strings.Contains(u, "@") && !strings.Contains(u, "\\") {
		userName = fmt.Sprintf("%s@%s", u, domainName)
	}

	return &GlobalCommand{
		DomainName: domainName,
		UserName:   userName,
		Password:   password,
		PassHash:   passHash,
		BaseDN:     baseDN,
		SSLConn:    ssl,
		Export:     export,
	}, nil
}
