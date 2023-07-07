package sddl

import (
	"errors"
	"fmt"
)

// ACL
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428
type ACL struct {
	AclRevision byte
	Sbz1        byte
	AclSize     [2]byte
	AceCount    [2]byte
	Sbz2        [2]byte
}

func (acl ACL) readACLHeader(data []byte) error {
	if len(data) != 8 {
		fmt.Printf("ACL header length error")
		return errors.New("bad ACL header length")
	}

	acl.AclRevision = data[0]
	acl.Sbz1 = data[1]
	acl.AclSize = [2]byte(data[2:4])
	acl.AceCount = [2]byte(data[4:6])
	acl.Sbz2 = [2]byte(data[6:8])

	return nil
}
