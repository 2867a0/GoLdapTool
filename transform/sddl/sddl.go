package sddl

import (
	"errors"
	"fmt"
	"goLdapTools/log"
	"goLdapTools/transform"
	"strings"
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
	// debug dump
	var nTSecurityDescriptorRawValue string
	for index, value := range sddlData {
		//nTSecurityDescriptorRawValue = nTSecurityDescriptorRawValue + fmt.Sprintf("0x%02x, ", value)
		nTSecurityDescriptorRawValue = nTSecurityDescriptorRawValue + fmt.Sprintf("%02x ", value)

		if (index+1)%16 == 0 {
			nTSecurityDescriptorRawValue = nTSecurityDescriptorRawValue + "\n"
		}
	}
	log.PrintDebugf("Debug Dump raw data:\n%s\n", nTSecurityDescriptorRawValue)

	// 解析 SecurityDescriptor 头
	sr := &SrSecurityDescriptor{RawData: sddlData}
	err := sr.readNtSecurityDescriptorHeader(sddlData[0:20])
	if err != nil {
		return nil, err
	}

	// 解析 Sacl 头
	sr.Sacl = &SaclStruct{
		Header: &AclHeader{
			Revision: 0,
			Sbz1:     0,
			AclSize:  nil,
			AceCount: nil,
			Sbz2:     nil,
		},
		Aces: []*AceStruct{},
	}
	saclDataOffset := int(sr.OffsetSacl.Value.(uint32))

	if saclDataOffset != 0 {
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
	} else {

	}

	// 解析Dacl
	sr.Dacl = &DaclStruct{
		Header: &AclHeader{
			Revision: 0,
			Sbz1:     0,
			AclSize:  nil,
			AceCount: nil,
			Sbz2:     nil,
		},
		Aces: []*AceStruct{},
	}
	daclDataOffset := int(sr.OffsetDacl.Value.(uint32))
	if daclDataOffset != 0 {
		err = sr.Dacl.Header.readACLHeader(sddlData[daclDataOffset : daclDataOffset+8])
		if err != nil {
			return nil, err
		}

		//解析Ace
		err = sr.Dacl.ResolveDaclAces(
			sddlData[daclDataOffset+8:daclDataOffset+int(sr.Dacl.Header.AclSize.Value.(uint32))], // 从ace起始地址开始读取
			int(sr.Dacl.Header.AceCount.Value.(uint32)))
		if err != nil {
			return nil, err
		}
	}

	// OwnerSid
	if sr.OffsetOwner.Value.(uint32) == 0 {
		sr.OwnerSid = &DataType{
			RawData: nil,
			Value:   nil,
		}
	} else {
		ownerSidSize := sr.OffsetGroup.Value.(uint32) - sr.OffsetOwner.Value.(uint32)
		sr.OwnerSid = &DataType{RawData: sddlData[sr.OffsetOwner.Value.(uint32) : sr.OffsetOwner.Value.(uint32)+ownerSidSize]}
		sr.OwnerSid.Value = transform.SidToString(sr.OwnerSid.RawData)
	}

	if sr.OffsetGroup.Value.(uint32) == 0 {
		sr.GroupSid = &DataType{
			RawData: nil,
			Value:   nil,
		}
	} else {
		// GroupSid
		sr.GroupSid = &DataType{RawData: sddlData[sr.OffsetGroup.Value.(uint32):]}
		sr.GroupSid.Value = transform.SidToString(sr.GroupSid.RawData)
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

// DataToString 打印，以字符串形式显示数据
func (sr *SrSecurityDescriptor) DataToString() strings.Builder {
	var sddlString strings.Builder

	// SecurityDescriptor头
	ownerSid := ""
	if sr.OwnerSid.RawData != nil {
		ownerSid = sr.OwnerSid.Value.(string)
	}
	groupSid := ""
	if sr.GroupSid.RawData != nil {
		groupSid = sr.GroupSid.Value.(string)
	}

	sddlString.WriteString(
		fmt.Sprintf("SecurityDescriptor header:\n"+
			"%4s%-20s%x\n"+
			"%4s%-20s%x\n"+
			"%4s%-20s%d\n"+
			"%4s%-20s%d\n"+
			"%4s%-20s%d\n"+
			"%4s%-20s%d\n"+
			"%4s%-20s%d\n"+
			"%4s%-20s%s\n"+
			"%4s%-20s%s\n\n",
			" ", "Revision:", sr.Revision,
			" ", "Sbz1:", sr.Sbz1,
			" ", "Control:", sr.Control.Value,
			" ", "OffsetOwner:", sr.OffsetOwner.Value,
			" ", "OffsetGroup:", sr.OffsetGroup.Value,
			" ", "OffsetSacl:", sr.OffsetSacl.Value,
			" ", "OffsetDacl", sr.OffsetDacl.Value,
			" ", "OwnerSid:", ownerSid,
			" ", "GroupSid:", groupSid))

	if sr.Sacl.Header.AclSize != nil {
		// Sacl头
		sddlString.WriteString(
			fmt.Sprintf("Sacl header:\n"+
				"%4s%-20s%x\n"+
				"%4s%-20s%x\n"+
				"%4s%-20s%d\n"+
				"%4s%-20s%d\n"+
				"%4s%-20s%d\n\n",
				" ", "Revision:", sr.Sacl.Header.Revision,
				" ", "Sbz1:", sr.Sacl.Header.Sbz1,
				" ", "Acl Size:", sr.Sacl.Header.AclSize.Value,
				" ", "Ace Count:", sr.Sacl.Header.AceCount.Value,
				" ", "Sbz2:", sr.Sacl.Header.Sbz2.Value))

		//Sacl Ace条目
		sddlString.WriteString(fmt.Sprintf("%4sAce(%d):\n", " ", len(sr.Sacl.Aces)))
		for index, ace := range sr.Sacl.Aces {
			sddlString.WriteString(
				fmt.Sprintf("%8s%d\n"+
					"%12s%-20s%x\n"+
					"%12s%-20s%x\n"+
					"%12s%-20s%d\n"+
					"%12s%-20s%d\n"+
					"%12s%-20s%s\n",
					" ", index+1,
					" ", "Ace Type:", ace.AceType,
					" ", "Ace Flags:", ace.AceFlags,
					" ", "Ace Size:", ace.AceSize.Value,
					" ", "Ace Mask:", ace.AceMask.Value,
					" ", "Extended:", ace.Extended.Value))

			if ace.ObjectType != nil {
				sddlString.WriteString(fmt.Sprintf("%12s%-20s%s\n", " ", "ObjectType:", ace.ObjectType.Value))
			}

			if ace.InheritedObjectType != nil {
				sddlString.WriteString(fmt.Sprintf("%12s%-20s%s\n", " ", "InheritedObjectType:", ace.InheritedObjectType.Value))
			}

			sddlString.WriteString(fmt.Sprintf("%12s%-20s%s\n\n", " ", "SID:", ace.SID.Value))
		}
	}

	// Dacl头
	if sr.Dacl.Header.AclSize != nil {
		sddlString.WriteString(
			fmt.Sprintf("Dacl header:\n"+
				"%4s%-20s%x\n"+
				"%4s%-20s%x\n"+
				"%4s%-20s%d\n"+
				"%4s%-20s%d\n"+
				"%4s%-20s%d\n\n",
				" ", "Revision:", sr.Dacl.Header.Revision,
				" ", "Sbz1:", sr.Dacl.Header.Sbz1,
				" ", "Acl Size:", sr.Dacl.Header.AclSize.Value,
				" ", "Ace Count:", sr.Dacl.Header.AceCount.Value,
				" ", "Sbz2:", sr.Dacl.Header.Sbz2.Value))

		//Dacl Ace条目
		sddlString.WriteString(fmt.Sprintf("%4sAce(%d):\n", " ", len(sr.Dacl.Aces)))
		for index, ace := range sr.Dacl.Aces {
			sddlString.WriteString(
				fmt.Sprintf("%8s%d\n"+
					"%12s%-20s%x\n"+
					"%12s%-20s%x\n"+
					"%12s%-20s%d\n"+
					"%12s%-20s%d\n"+
					"%12s%-20s%s\n",
					" ", index+1,
					" ", "Ace Type:", ace.AceType,
					" ", "Ace Flags:", ace.AceFlags,
					" ", "Ace Size:", ace.AceSize.Value,
					" ", "Ace Mask:", ace.AceMask.Value,
					" ", "Extended:", ace.Extended.Value))

			if ace.ObjectType != nil {
				sddlString.WriteString(fmt.Sprintf("%12s%-20s%s\n", " ", "ObjectType:", ace.ObjectType.Value))
			}

			if ace.InheritedObjectType != nil {
				sddlString.WriteString(fmt.Sprintf("%12s%-20s%s\n", " ", "InheritedObjectType:", ace.InheritedObjectType.Value))
			}

			sddlString.WriteString(fmt.Sprintf("%12s%-20s%s\n\n", " ", "SID:", ace.SID.Value))
		}
	}
	return sddlString
}
