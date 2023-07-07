package sddl

import (
	"errors"
	"fmt"
)

// SrSecurityDescriptor
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d
type SrSecurityDescriptor struct {
	Revision    byte
	Sbz1        byte
	Control     [2]byte // TODO resolve this value
	OffsetOwner [4]byte
	OffsetGroup [4]byte
	OffsetSacl  [4]byte
	OffsetDacl  [4]byte
	Sacl        interface{}
	Dacl        interface{}
	OwnerSid    interface{}
	GroupSid    interface{}
}

func NewSecurityDescriptor(sddl_data []byte) (*SrSecurityDescriptor, error) {
	sr := &SrSecurityDescriptor{}
	err := sr.readNtSecurityDescriptorHeader(sddl_data[0:20])
	if err != nil {
		return nil, err
	}

	acl := &ACL{}
	err = acl.readACLHeader(sddl_data[20:29])
	if err != nil {
		return nil, err
	}

	ace := &ACE{}
	err = ace.readACEHeader(sddl_data[29:34])
	if err != nil {
		return nil, err
	}

	return sr, nil
}

// 读取NtSecurityDescriptor 头
func (sr *SrSecurityDescriptor) readNtSecurityDescriptorHeader(data []byte) error {
	if len(data) != 20 {
		fmt.Printf("NtSecurityDescriptor header length error")
		return errors.New("header length error")
	}

	sr.Revision = data[0]
	sr.Sbz1 = data[1]
	sr.Control = [2]byte(data[2:4])
	sr.OffsetOwner = [4]byte(data[4:8])
	sr.OffsetGroup = [4]byte(data[8:12])
	sr.OffsetSacl = [4]byte(data[12:16])
	sr.OffsetDacl = [4]byte(data[16:20])

	return nil
}

func TransformRawSDDL(b []byte) string {
	return ""
}
