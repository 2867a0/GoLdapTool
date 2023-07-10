package sddl

import (
	"errors"
	"fmt"
	"goLdapTools/transform"
)

// AclHeader
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428
type AclHeader struct {
	Revision byte
	Sbz1     byte
	// 2 Bits
	AclSize *DataType
	// 2 Bits
	AceCount *DataType
	// 2 Bits
	Sbz2 *DataType
}

type SaclStruct struct {
	// 8 Bits
	Header *AclHeader
	Aces   []*AceStruct
}

type DaclStruct struct {
	// 8 Bits
	Header *AclHeader
	Aces   []*AceStruct
}

func (acl *AclHeader) readACLHeader(data []byte) error {
	if len(data) != 8 {
		fmt.Printf("AclHeader header length error")
		return errors.New("bad AclHeader header length")
	}

	var err error

	acl.Revision = data[0]
	acl.Sbz1 = data[1]

	acl.AclSize = &DataType{RawData: data[2:4]}
	acl.AclSize.Value, err = getValue(acl.AclSize.RawData[:])
	if err != nil {
		return err
	}

	acl.AceCount = &DataType{RawData: data[4:6]}
	acl.AceCount.Value, err = getValue(acl.AceCount.RawData[:])
	if err != nil {
		return err
	}

	acl.Sbz2 = &DataType{RawData: data[6:8]}
	acl.Sbz2.Value, err = getValue(acl.Sbz2.RawData[:])
	if err != nil {
		return err
	}

	return nil
}

func (sacl *SaclStruct) ResolveSaclAces(allData []byte, aceCount int) error {
	offset := 0
	for i := 0; i < aceCount; i++ {
		aceSize, err := getValue(allData[offset+2 : offset+4])
		if err != nil {
			return errors.New(fmt.Sprintf("%s%d\n%s\n", "get ace offset error: ", offset, err.Error()))
		}
		ace, err := aceResolve(allData[offset:offset+int(aceSize)], int(aceSize))
		if err != nil {
			return err
		}

		sacl.Aces = append(sacl.Aces, ace)
		offset = offset + int(aceSize)
	}

	return nil
}

func (dacl *DaclStruct) ResolveDaclAces(allData []byte, aceCount int) error {
	offset := 0
	for i := 0; i < aceCount; i++ {
		aceSize, err := getValue(allData[offset+2 : offset+4])
		if err != nil {
			return errors.New(fmt.Sprintf("%s%d\n%s\n", "get ace offset error: ", offset, err.Error()))
		}
		ace, err := aceResolve(allData[offset:offset+int(aceSize)], int(aceSize))
		if err != nil {
			//return errors.New(fmt.Sprintf("resolveDaclAces:%d - %s\n", i, err.Error()))
			fmt.Printf(fmt.Sprintf("resolveDaclAces:%d - %s\n", i, err.Error()))
		}

		dacl.Aces = append(dacl.Aces, ace)
		offset = offset + int(aceSize)
	}

	return nil
}

func aceResolve(aceData []byte, aceSize int) (*AceStruct, error) {
	if len(aceData) != aceSize {
		return nil, errors.New("The actual size of ace does not match the input size")
	}

	ace := &AceStruct{}
	var err error

	ace.AceType = aceData[0]
	ace.AceFlags = aceData[1]

	ace.AceSize = &DataType{RawData: aceData[2:4]}
	ace.AceSize.Value, err = getValue(ace.AceSize.RawData[:])
	if err != nil {
		return nil, err
	}

	ace.AceMask = &AceMaskStruct{}
	ace.AceMask.RawData = aceData[4:8]
	ace.AceMask.Value, err = getValue(ace.AceMask.RawData[:])
	if err != nil {
		return nil, err
	}

	ace.Extended = &DataType{RawData: aceData[8:12]}
	ace.Extended.Value, err = getValue(ace.Extended.RawData[:])
	if err != nil {
		return nil, err
	}

	extended := 0
	size := 8
	switch int(ace.Extended.Value.(uint32)) {
	case 1:
		// ObjectType
		ace.ObjectType = &DataType{RawData: aceData[12:28]}
		ace.ObjectType.Value, err = GuidToString(ace.ObjectType.RawData)
		if err != nil {
			return nil, err
		}

		extended = 20
		ace.Extended.Value = "ObjectType"
	case 2:
		//InheritedObjectType
		ace.InheritedObjectType = &DataType{RawData: aceData[12:28]}
		ace.InheritedObjectType.Value, err = GuidToString(ace.InheritedObjectType.RawData)
		if err != nil {
			return nil, err
		}

		extended = 20
		ace.Extended.Value = "InheritedObjectType"
	case 3:
		// ObjectType + InheritedObjectType
		ace.ObjectType = &DataType{RawData: aceData[12:28]}
		ace.ObjectType.Value, err = GuidToString(ace.ObjectType.RawData)
		if err != nil {
			return nil, err
		}

		ace.InheritedObjectType = &DataType{RawData: aceData[28:44]}
		ace.InheritedObjectType.Value, err = GuidToString(ace.InheritedObjectType.RawData)
		if err != nil {
			return nil, err
		}

		extended = 36
		ace.Extended.Value = "ObjectType + InheritedObjectType"
	default:
		// 无扩展，后面就直接是SID
		//fmt.Printf("====dump====\n    ")
		//for i, v := range aceData {
		//	fmt.Printf("%02x ", v)
		//
		//	if (i+1)%16 == 0 {
		//		fmt.Printf("\n    ")
		//	}
		//}
		//fmt.Printf("\n")
		//return nil, errors.New(fmt.Sprintf("error extended type: %x\n", ace.Extended.RawData))
		ace.Extended.Value = "NULL"

	}

	ace.SID = &DataType{RawData: aceData[size+extended:]}
	ace.SID.Value = transform.SidToString(ace.SID.RawData[:])

	return ace, nil
}
