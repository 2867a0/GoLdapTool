package sddl

import (
	"errors"
	"fmt"
	"goLdapTools/log"
	"goLdapTools/transform/sddl/acl"
	"goLdapTools/transform/sddl/datatype"
	"goLdapTools/transform/sddl/sid"
	"strings"
)

// SrSecurityDescriptor
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d
type SrSecurityDescriptor struct {
	Revision byte
	Sbz1     byte
	// 2 Bits
	Control *datatype.DataType
	// 4 Bits
	OffsetOwner *datatype.DataType
	// 4 Bits
	OffsetGroup *datatype.DataType
	// 4 Bits
	OffsetSacl *datatype.DataType
	// 4 Bits
	OffsetDacl *datatype.DataType

	OwnerSid *datatype.DataType
	GroupSid *datatype.DataType

	// Sacl 头和数据
	Sacl *acl.SaclHeader
	// Dacl 头和数据
	Dacl *acl.DaclHeader

	// 头原始数据大小为20字节
	RawData []byte
}

// NewSecurityDescriptor 接受sddl原始数据，返回解析后的数据结构
func NewSecurityDescriptor(sddlData []byte) (*SrSecurityDescriptor, error) {
	// debug dump
	if sddlData != nil {
		var nTSecurityDescriptorRawValue string
		for index, value := range sddlData {
			//nTSecurityDescriptorRawValue = nTSecurityDescriptorRawValue + fmt.Sprintf("0x%02x, ", value)
			nTSecurityDescriptorRawValue = nTSecurityDescriptorRawValue + fmt.Sprintf("%02x ", value)

			if (index+1)%16 == 0 {
				nTSecurityDescriptorRawValue = nTSecurityDescriptorRawValue + "\n"
			}
		}
		log.PrintDebugf("Debug Dump raw data:\n%s\n", nTSecurityDescriptorRawValue)
	}

	// 解析 SecurityDescriptor 头
	sr := &SrSecurityDescriptor{RawData: sddlData[0:20]}
	err := sr.initNtSecurityDescriptorHeader()
	if err != nil {
		return nil, err
	}

	// 解析 Sacl 头
	saclDataOffset := int(sr.OffsetSacl.Value.(uint32))
	if saclDataOffset != 0 {
		sr.Sacl, err = acl.NewSaclHeader(sddlData[saclDataOffset : saclDataOffset+8])
		if err != nil {
			return nil, err
		}

		// 解析ACE
		err = sr.Sacl.ResolveSaclAces(
			sddlData[saclDataOffset+8:saclDataOffset+8+int(sr.Sacl.AclSize.Value.(uint16))], // 从ace起始地址开始读取
			int(sr.Sacl.AceCount.Value.(uint16)))
		if err != nil {
			return nil, err
		}
	} else {
		sr.Sacl, err = acl.NewSaclHeader(nil)
		if err != nil {
			return nil, err
		}
	}

	// 解析Dacl
	daclDataOffset := int(sr.OffsetDacl.Value.(uint32))
	if daclDataOffset != 0 {
		sr.Dacl, err = acl.NewDaclHeader(sddlData[daclDataOffset : daclDataOffset+8])
		if err != nil {
			return nil, err
		}

		//解析Ace
		err = sr.Dacl.ResolveDaclAces(
			sddlData[daclDataOffset+8:daclDataOffset+int(sr.Dacl.AclSize.Value.(uint16))], // 从ace起始地址开始读取
			int(sr.Dacl.AceCount.Value.(uint16)))
		if err != nil {
			return nil, err
		}
	} else {
		sr.Dacl, err = acl.NewDaclHeader(nil)
		if err != nil {
			return nil, err
		}
	}

	// OwnerSid
	sr.OwnerSid = &datatype.DataType{
		RawData: nil,
		Value:   nil,
	}
	if sr.OffsetOwner.Value.(uint32) != 0 {
		sr.OwnerSid.Value, sr.OwnerSid.RawData = sid.SidToString(sddlData[sr.OffsetOwner.Value.(uint32):])
	}

	// GroupSid
	sr.GroupSid = &datatype.DataType{}
	if sr.OffsetGroup.Value.(uint32) != 0 {
		sr.GroupSid.Value, sr.GroupSid.RawData = sid.SidToString(sddlData[sr.OffsetGroup.Value.(uint32):])
	}

	return sr, nil
}

// 读取NtSecurityDescriptor 头
func (sr *SrSecurityDescriptor) initNtSecurityDescriptorHeader() error {
	if len(sr.RawData) != 20 {
		fmt.Printf("NtSecurityDescriptor header length error")
		return errors.New("header length error")
	}

	sr.Revision = sr.RawData[0]
	sr.Sbz1 = sr.RawData[1]

	sr.Control = &datatype.DataType{RawData: sr.RawData[2:4]}
	cValue, err := datatype.GetValue(sr.Control.RawData[:])
	if err != nil {
		return err
	}

	sr.Control.Value = cValue

	sr.OffsetOwner = &datatype.DataType{RawData: sr.RawData[4:8]}
	oValue, err := datatype.GetValue(sr.OffsetOwner.RawData[:])
	if err != nil {
		return err
	}

	sr.OffsetOwner.Value = oValue

	sr.OffsetGroup = &datatype.DataType{RawData: sr.RawData[8:12]}
	gValue, err := datatype.GetValue(sr.OffsetGroup.RawData[:])
	if err != nil {
		return err
	}

	sr.OffsetGroup.Value = gValue

	sr.OffsetSacl = &datatype.DataType{RawData: sr.RawData[12:16]}
	sValue, err := datatype.GetValue(sr.OffsetSacl.RawData[:])
	if err != nil {
		return err
	}

	sr.OffsetSacl.Value = sValue

	sr.OffsetDacl = &datatype.DataType{RawData: sr.RawData[16:20]}
	dValue, err := datatype.GetValue(sr.OffsetDacl.RawData[:])
	if err != nil {
		return err
	}

	sr.OffsetDacl.Value = dValue

	return nil
}

// DataToString 打印，以字符串形式显示sddl数据
func (sr *SrSecurityDescriptor) DataToString(sddlData []byte) strings.Builder {
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

	if sr.Sacl.AclSize.Value != 0 {
		// Sacl头
		sddlString.WriteString(
			fmt.Sprintf("Sacl header:\n"+
				"%4s%-20s%x\n"+
				"%4s%-20s%x\n"+
				"%4s%-20s%d\n"+
				"%4s%-20s%d\n"+
				"%4s%-20s%d\n\n",
				" ", "Revision:", sr.Sacl.Revision,
				" ", "Sbz1:", sr.Sacl.Sbz1,
				" ", "Acl Size:", sr.Sacl.AclSize.Value,
				" ", "Ace Count:", sr.Sacl.AceCount.Value,
				" ", "Sbz2:", sr.Sacl.Sbz2.Value))

		//Sacl Ace条目
		sddlString.WriteString(fmt.Sprintf("%4sAce(%d):\n", " ", len(sr.Sacl.Aces)))
		for index, ace := range sr.Sacl.Aces {
			aceMaskString, err := ace.AceMask.GetAceMaskString()
			if err != nil {
				log.PrintErrorf("get ace mask string error: %s", err)
			}
			sddlString.WriteString(
				fmt.Sprintf("%8s%d\n"+
					"%12s%-20s%x\n"+
					"%12s%-20s%x\n"+
					"%12s%-20s%d\n"+
					"%12s%-20s%d(%s)\n"+
					"%12s%-20s%s\n",
					" ", index+1,
					" ", "Ace Type:", ace.AceType,
					" ", "Ace Flags:", ace.AceFlags,
					" ", "Ace Size:", ace.AceSize.Value,
					" ", "Ace Mask:", ace.AceMask.Value, aceMaskString,
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
	if sr.Dacl.AclSize != nil {
		sddlString.WriteString(
			fmt.Sprintf("Dacl header:\n"+
				"%4s%-20s%x\n"+
				"%4s%-20s%x\n"+
				"%4s%-20s%d\n"+
				"%4s%-20s%d\n"+
				"%4s%-20s%d\n\n",
				" ", "Revision:", sr.Dacl.Revision,
				" ", "Sbz1:", sr.Dacl.Sbz1,
				" ", "Acl Size:", sr.Dacl.AclSize.Value,
				" ", "Ace Count:", sr.Dacl.AceCount.Value,
				" ", "Sbz2:", sr.Dacl.Sbz2.Value))

		//Dacl Ace条目
		sddlString.WriteString(fmt.Sprintf("%4sAce(%d):\n", " ", len(sr.Dacl.Aces)))
		for index, ace := range sr.Dacl.Aces {
			aceMaskString, err := ace.AceMask.GetAceMaskString()
			if err != nil {
				log.PrintErrorf("get ace mask string error: %s", err)
			}

			sddlString.WriteString(
				fmt.Sprintf("%8s%d\n"+
					"%12s%-20s%x\n"+
					"%12s%-20s%x\n"+
					"%12s%-20s%d\n"+
					"%12s%-20s%d(%s)\n"+
					"%12s%-20s%s\n",
					" ", index+1,
					" ", "Ace Type:", ace.AceType,
					" ", "Ace Flags:", ace.AceFlags,
					" ", "Ace Size:", ace.AceSize.Value,
					" ", "Ace Mask:", ace.AceMask.Value, aceMaskString,
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

// 更新原始数据

// GetData 提取sddl数据, 返回提取后的原始数据
func (sr *SrSecurityDescriptor) GetData() ([]byte, error) {
	var data []byte

	data = append(data, sr.Revision)
	data = append(data, sr.Sbz1)
	data = append(data, sr.Control.RawData...)
	data = append(data, sr.OffsetOwner.RawData...)
	data = append(data, sr.OffsetGroup.RawData...)
	data = append(data, sr.OffsetSacl.RawData...)
	data = append(data, sr.OffsetDacl.RawData...)

	//Sacl
	if sr.Sacl.AclSize != nil {
		data = append(data, sr.Sacl.RawData...)

		for _, ace := range sr.Sacl.Aces {
			data = append(data, ace.RawData...)
		}
	}

	//Dacl
	if sr.Dacl.AclSize != nil {
		data = append(data, sr.Dacl.RawData...)

		for _, ace := range sr.Dacl.Aces {
			data = append(data, ace.RawData...)
		}
	}

	// owner sid
	if sr.OffsetOwner.Value.(uint32) != 0 {
		ownerSidRaw, err := sid.StringToSid(sr.OwnerSid.Value.(string))
		if err != nil {
			return nil, err
		}
		data = append(data, ownerSidRaw...)
	}

	// group sid
	if sr.OffsetGroup.Value.(uint32) != 0 {
		groupSidRaw, err := sid.StringToSid(sr.GroupSid.Value.(string))
		if err != nil {
			return nil, err
		}
		data = append(data, groupSidRaw...)
	}

	return data, nil
}
