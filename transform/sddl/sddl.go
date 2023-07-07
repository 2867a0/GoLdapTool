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
	Control     *SecurityDescriptorControl // TODO resolve this value
	OffsetOwner [4]byte
	OffsetGroup [4]byte
	OffsetSacl  [4]byte
	OffsetDacl  [4]byte
	Sacl        interface{}
	Dacl        interface{}
	OwnerSid    interface{}
	GroupSid    interface{}

	RawData []byte
}

type SecurityDescriptorControl struct {
	ControlString string
	RawData       [2]byte
}

func NewSecurityDescriptor(sddl_data []byte) (*SrSecurityDescriptor, error) {
	sr := &SrSecurityDescriptor{RawData: sddl_data}
	err := sr.readNtSecurityDescriptorHeader(sddl_data[0:20])
	if err != nil {
		return nil, err
	}

	acl := &ACL{}
	err = acl.readACLHeader(sddl_data[20:28])
	if err != nil {
		return nil, err
	}

	ace := &ACE{}
	err = ace.readACEHeader(sddl_data[28:32])
	if err != nil {
		return nil, err
	}

	aceMask := &AceMask{}
	err = aceMask.readACEMask(sddl_data[32:36])
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

	control := &SecurityDescriptorControl{RawData: [2]byte(data[2:4])}
	control.resolveControl()

	sr.Control = control
	sr.OffsetOwner = [4]byte(data[4:8])
	sr.OffsetGroup = [4]byte(data[8:12])
	sr.OffsetSacl = [4]byte(data[12:16])
	sr.OffsetDacl = [4]byte(data[16:20])

	return nil
}

func (sdc *SecurityDescriptorControl) resolveControl() {
	_ = uint16(sdc.RawData[0]) | uint16(sdc.RawData[1])<<8

}

func (sr *SrSecurityDescriptor) Dump() {
	for index, d := range sr.RawData {
		fmt.Printf("%02x ", d)

		if (index+1)%16 == 0 {
			fmt.Printf("\n")
		}
	}

	//SecurityDescriptor

}

func TransformRawSDDL(b []byte) string {
	return ""
}
