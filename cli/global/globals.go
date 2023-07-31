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
		baseDN = fmt.Sprintf("dc=%s,dc=%s", domainNameArr[len(domainNameArr)-2], domainNameArr[len(domainNameArr)-1])
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

	userName := fmt.Sprintf("%s@%s.%s", u, domainNameArr[len(domainNameArr)-2], domainNameArr[len(domainNameArr)-1])
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
