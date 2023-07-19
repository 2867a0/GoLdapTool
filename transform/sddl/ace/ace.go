package ace

import (
	"encoding/binary"
	"goLdapTools/transform/sddl/datatype"
	"goLdapTools/transform/sddl/guid"
	"goLdapTools/transform/sddl/sid"
	"strings"
)

type AceStruct struct {
	AceType  byte
	AceFlags byte
	AceSize  *datatype.DataType
	// 4 Bits
	AceMask  *AceMaskStruct //TODO resolve data to string
	Extended *datatype.DataType
	// 16 Bits
	ObjectType *datatype.DataType
	// 16 Bits
	InheritedObjectType *datatype.DataType
	SID                 *datatype.DataType

	RawData []byte
}

func NewAceStruct() *AceStruct {
	return &AceStruct{
		AceType:  0,
		AceFlags: 0,
		AceSize: &datatype.DataType{
			RawData: []byte{0, 0},
			Value:   nil,
		},
		AceMask: &AceMaskStruct{datatype.DataType{
			RawData: []byte{0, 0, 0, 0},
			Value:   nil,
		}},
		Extended: &datatype.DataType{
			RawData: []byte{0, 0, 0, 0},
			Value:   nil,
		},
		ObjectType:          nil,
		InheritedObjectType: nil,
		SID: &datatype.DataType{
			RawData: []byte{},
			Value:   nil,
		},

		RawData: []byte{},
	}
}

// 字符串转换为字节
//func (ace *AceStruct) ToData() []byte {
//	data := []byte{}
//
//	data = append(data, ace.AceType)
//	data = append(data, ace.AceFlags)
//
//	data = append(data, ace.AceSize.RawData...)
//	data = append(data, ace.AceMask.RawData...)
//
//	if ace.Extended != nil {
//		data = append(data, ace.Extended.RawData...)
//	}
//
//	if ace.ObjectType != nil {
//		data = append(data, ace.ObjectType.RawData...)
//	}
//
//	if ace.InheritedObjectType != nil {
//		data = append(data, ace.InheritedObjectType.RawData...)
//	}
//
//	data = append(data, ace.SID.RawData...)
//
//	return data
//}

// 根据string数据更新原始数据
func (ace *AceStruct) Update() error {
	var err error

	//ace mask
	aceMaskRaw := make([]byte, 4)
	binary.LittleEndian.PutUint32(aceMaskRaw, ace.AceMask.Value.(uint32))
	ace.AceMask.RawData = aceMaskRaw

	// extended
	extendedSize := 0
	extendedRaw := make([]byte, 4)
	if ace.Extended == nil {
		extendedSize += 4
	} else if strings.EqualFold(ace.Extended.Value.(string), "objecttype") {
		binary.LittleEndian.PutUint32(extendedRaw, 1)
		extendedSize += 20
	} else if strings.EqualFold(ace.Extended.Value.(string), "inheritedobjecttype") {
		binary.LittleEndian.PutUint32(extendedRaw, 2)
		extendedSize += 20
	} else {
		binary.LittleEndian.PutUint32(extendedRaw, 3)
		extendedSize += 36
	}
	ace.Extended.RawData = extendedRaw

	if ace.ObjectType != nil {
		ace.ObjectType.RawData, err = guid.StringToGuid(ace.ObjectType.Value.(string))
		if err != nil {
			return err
		}
	}

	if ace.InheritedObjectType != nil {
		ace.InheritedObjectType.RawData, err = guid.StringToGuid(ace.InheritedObjectType.Value.(string))
		if err != nil {
			return err
		}
	}

	sidRaw, err := sid.StringToSid(ace.SID.Value.(string))
	if err != nil {
		return err
	}
	ace.SID.RawData = sidRaw

	ace.AceSize.Value = uint16(1 + 1 + len(ace.AceSize.RawData) + len(ace.AceMask.RawData) + extendedSize + len(ace.SID.RawData))
	aceSizeRawData := make([]byte, 2)
	binary.LittleEndian.PutUint16(aceSizeRawData, ace.AceSize.Value.(uint16))
	ace.AceSize.RawData = aceSizeRawData

	ace.RawData = append(ace.RawData, ace.AceType)
	ace.RawData = append(ace.RawData, ace.AceFlags)
	ace.RawData = append(ace.RawData, ace.AceSize.RawData...)
	ace.RawData = append(ace.RawData, ace.AceMask.RawData...)
	ace.RawData = append(ace.RawData, ace.Extended.RawData...)
	if ace.ObjectType != nil {
		ace.RawData = append(ace.RawData, ace.ObjectType.RawData...)
	}
	if ace.InheritedObjectType != nil {
		ace.RawData = append(ace.RawData, ace.InheritedObjectType.RawData...)
	}
	ace.RawData = append(ace.RawData, ace.SID.RawData...)

	return nil
}
