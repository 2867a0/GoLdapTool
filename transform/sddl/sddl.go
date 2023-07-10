package sddl

import (
	"errors"
	"fmt"
	"goLdapTools/transform"
)

// SrSecurityDescriptor
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d
type SrSecurityDescriptor struct {
	Revision byte
	Sbz1     byte
	// 2 Bits
	Control *DataType
	// 4 Bits
	OffsetOwner *DataType
	// 4 Bits
	OffsetGroup *DataType
	// 4 Bits
	OffsetSacl *DataType
	// 4 Bits
	OffsetDacl *DataType

	OwnerSid *DataType
	GroupSid *DataType

	// Sacl 头和数据
	Sacl *SaclStruct
	// Dacl 头和数据
	Dacl *DaclStruct

	RawData []byte
}

func NewSecurityDescriptor(sddlData []byte) (*SrSecurityDescriptor, error) {
	// 解析 SecurityDescriptor 头
	sr := &SrSecurityDescriptor{RawData: sddlData}
	err := sr.readNtSecurityDescriptorHeader(sddlData[0:20])
	if err != nil {
		return nil, err
	}

	// 解析 Sacl 头
	sr.Sacl = &SaclStruct{Header: &AclHeader{}}
	saclDataOffset := int(sr.OffsetSacl.Value.(uint32))
	err = sr.Sacl.Header.readACLHeader(sddlData[saclDataOffset : saclDataOffset+8]) //[20:28]
	if err != nil {
		return nil, err
	}

	// 解析ACE
	err = sr.Sacl.ResolveSaclAces(
		sddlData[saclDataOffset+8:saclDataOffset+8+int(sr.Sacl.Header.AclSize.Value.(uint32))], // 从ace起始地址开始读取
		int(sr.Sacl.Header.AceCount.Value.(uint32)))
	if err != nil {
		return nil, err
	}

	// 解析Dacl
	sr.Dacl = &DaclStruct{Header: &AclHeader{}}
	daclDataOffset := int(sr.OffsetDacl.Value.(uint32))
	err = sr.Dacl.Header.readACLHeader(sddlData[daclDataOffset : daclDataOffset+8])
	if err != nil {
		return nil, err
	}

	//解析Ace
	err = sr.Dacl.ResolveDaclAces(
		sddlData[daclDataOffset+8:daclDataOffset+8+int(sr.Dacl.Header.AclSize.Value.(uint32))], // 从ace起始地址开始读取
		int(sr.Dacl.Header.AceCount.Value.(uint32)))
	if err != nil {
		return nil, err
	}

	// OwnerSid
	ownerSidSize := sr.OffsetGroup.Value.(uint32) - sr.OffsetOwner.Value.(uint32)
	sr.OwnerSid = &DataType{RawData: sddlData[sr.OffsetOwner.Value.(uint32) : sr.OffsetOwner.Value.(uint32)+ownerSidSize]}
	sr.OwnerSid.Value = transform.SidToString(sr.OwnerSid.RawData)

	// GroupSid
	sr.GroupSid = &DataType{RawData: sddlData[sr.OffsetGroup.Value.(uint32):]}
	sr.GroupSid.Value = transform.SidToString(sr.GroupSid.RawData)

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

	sr.Control = &DataType{RawData: data[2:4]}
	cValue, err := getValue(sr.Control.RawData[:])
	if err != nil {
		return err
	}

	sr.Control.Value = cValue

	sr.OffsetOwner = &DataType{RawData: data[4:8]}
	oValue, err := getValue(sr.OffsetOwner.RawData[:])
	if err != nil {
		return err
	}

	sr.OffsetOwner.Value = oValue

	sr.OffsetGroup = &DataType{RawData: data[8:12]}
	gValue, err := getValue(sr.OffsetGroup.RawData[:])
	if err != nil {
		return err
	}

	sr.OffsetGroup.Value = gValue

	sr.OffsetSacl = &DataType{RawData: data[12:16]}
	sValue, err := getValue(sr.OffsetSacl.RawData[:])
	if err != nil {
		return err
	}

	sr.OffsetSacl.Value = sValue

	sr.OffsetDacl = &DataType{RawData: data[16:20]}
	dValue, err := getValue(sr.OffsetDacl.RawData[:])
	if err != nil {
		return err
	}

	sr.OffsetDacl.Value = dValue

	return nil
}

// 打印，以字符串形式显示数据
func (sr *SrSecurityDescriptor) Dump() error {
	return nil
}
