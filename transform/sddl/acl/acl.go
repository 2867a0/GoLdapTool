package acl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"goLdapTools/transform/sddl/ace"
	"goLdapTools/transform/sddl/datatype"
	"goLdapTools/transform/sddl/guid"
	"goLdapTools/transform/sddl/sid"
)

// AclHeader
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428
type AclHeader struct {
	Revision byte
	Sbz1     byte
	// 2 Bits
	AclSize *datatype.DataType
	// 2 Bits
	AceCount *datatype.DataType
	// 2 Bits
	Sbz2 *datatype.DataType
}

type SaclHeader struct {
	// 8 Bits
	*AclHeader
	Aces []*ace.AceStruct

	RawData []byte
}

type DaclHeader struct {
	// 8 Bits
	*AclHeader
	Aces []*ace.AceStruct

	RawData []byte
}

func NewSaclHeader(data []byte) (*SaclHeader, error) {

	sacl := &SaclHeader{
		AclHeader: &AclHeader{
			Revision: 0,
			Sbz1:     0,
			AclSize:  nil,
			AceCount: nil,
			Sbz2:     nil,
		},
		Aces:    []*ace.AceStruct{},
		RawData: []byte{},
	}

	if data != nil {
		sacl.RawData = data
		err := sacl.initACLHeader(sacl.RawData)
		if err != nil {
			return nil, err
		}
	}

	return sacl, nil
}

func NewDaclHeader(data []byte) (*DaclHeader, error) {

	dacl := &DaclHeader{
		AclHeader: &AclHeader{
			Revision: 0,
			Sbz1:     0,
			AclSize: &datatype.DataType{
				RawData: []byte{},
				Value:   nil,
			},
			AceCount: &datatype.DataType{
				RawData: []byte{},
				Value:   nil,
			},
			Sbz2: &datatype.DataType{
				RawData: []byte{},
				Value:   nil,
			},
		},
		Aces:    []*ace.AceStruct{},
		RawData: []byte{},
	}

	if data != nil {
		dacl.RawData = data
		err := dacl.initACLHeader(dacl.RawData)
		if err != nil {
			return nil, err
		}
	}

	return dacl, nil
}

func (sacl *SaclHeader) ResolveSaclAces(allData []byte, aceCount int) error {
	offset := 0
	for i := 0; i < aceCount; i++ {
		aceSize, err := datatype.GetValue(allData[offset+2 : offset+4])
		if err != nil {
			return errors.New(fmt.Sprintf("%s%d\n%s\n", "get ace offset error: ", offset, err.Error()))
		}
		ace, err := aceResolve(allData[offset:offset+int(aceSize.(uint16))], int(aceSize.(uint16)))
		if err != nil {
			return err
		}

		sacl.Aces = append(sacl.Aces, ace)
		offset = offset + int(aceSize.(uint16))
	}

	return nil
}

// AddAce 添加一条Ace，返回添加的大小
func (sacl *SaclHeader) AddAce(sid string, objectType string) (uint16, error) {
	// 新建Ace结构
	var err error

	// TODO change hardcode
	aceEntry := ace.NewAceStruct()
	aceEntry.AceType = 5
	aceEntry.AceMask.Value = uint32(256)
	aceEntry.Extended.Value = "ObjectType"
	aceEntry.ObjectType = &datatype.DataType{
		RawData: []byte{},
		Value:   objectType,
	}
	aceEntry.SID.Value = sid

	// ace转换成字节
	err = aceEntry.Update()
	if err != nil {
		return 0, err
	}

	// 写入Ace到Dacl.Aces中
	sacl.Aces = append(sacl.Aces, aceEntry)

	// 更新Ace数量、大小,更新nTSecurityDescriptor头中的数据偏移(Dacl、offsetOwner、offsetGroup)
	sacl.AceCount.Value = sacl.AceCount.Value.(uint16) + 1
	sacl.AclSize.Value = sacl.AclSize.Value.(uint16) + aceEntry.AceSize.Value.(uint16)
	sacl.update()

	return aceEntry.AceSize.Value.(uint16), nil
}

// 根据value更新RawData
func (sacl *SaclHeader) update() {
	aclSizeRaw := make([]byte, 2)
	binary.LittleEndian.PutUint16(aclSizeRaw, sacl.AclSize.Value.(uint16))
	sacl.AclSize.RawData = aclSizeRaw

	aceCountRaw := make([]byte, 2)
	binary.LittleEndian.PutUint16(aceCountRaw, sacl.AceCount.Value.(uint16))
	sacl.AceCount.RawData = aceCountRaw

	daclRaw := []byte{}
	daclRaw = append(daclRaw, sacl.Revision)
	daclRaw = append(daclRaw, sacl.Sbz1)
	daclRaw = append(daclRaw, sacl.AclSize.RawData...)
	daclRaw = append(daclRaw, sacl.AceCount.RawData...)
	daclRaw = append(daclRaw, sacl.Sbz2.RawData...)

	sacl.RawData = daclRaw
}

func (dacl *DaclHeader) ResolveDaclAces(allData []byte, aceCount int) error {
	offset := 0
	for i := 0; i < aceCount; i++ {
		aceSize, err := datatype.GetValue(allData[offset+2 : offset+4])
		if err != nil {
			return errors.New(fmt.Sprintf("%s%d\n%s\n", "get ace offset error: ", offset, err.Error()))
		}
		ace, err := aceResolve(allData[offset:offset+int(aceSize.(uint16))], int(aceSize.(uint16)))
		if err != nil {
			//return errors.New(fmt.Sprintf("resolveDaclAces:%d - %s\n", i, err.Error()))
			fmt.Printf(fmt.Sprintf("resolveDaclAces:%d - %s\n", i, err.Error()))
		}

		dacl.Aces = append(dacl.Aces, ace)
		offset = offset + int(aceSize.(uint16))
	}

	return nil
}

// AddAce 添加一条Ace，返回添加的大小
func (dacl *DaclHeader) AddAce(sid string, objectType string) (uint16, error) {
	// 新建Ace结构
	var err error

	ace := ace.NewAceStruct()
	ace.AceType = 5
	ace.AceMask.Value = uint32(256)
	ace.Extended.Value = "ObjectType"
	ace.ObjectType = &datatype.DataType{
		RawData: []byte{},
		Value:   objectType,
	}
	ace.SID.Value = sid

	// ace转换成字节
	err = ace.Update()
	if err != nil {
		return 0, err
	}

	// 写入Ace到Dacl.Aces中
	dacl.Aces = append(dacl.Aces, ace)

	// 更新Ace数量、大小,更新Dacl
	dacl.AceCount.Value = dacl.AceCount.Value.(uint16) + 1
	dacl.AclSize.Value = dacl.AclSize.Value.(uint16) + ace.AceSize.Value.(uint16)
	dacl.update()

	return ace.AceSize.Value.(uint16), nil
}

// 根据value更新RawData
func (dacl *DaclHeader) update() {
	aclSizeRaw := make([]byte, 2)
	binary.LittleEndian.PutUint16(aclSizeRaw, dacl.AclSize.Value.(uint16))
	dacl.AclSize.RawData = aclSizeRaw

	aceCountRaw := make([]byte, 2)
	binary.LittleEndian.PutUint16(aceCountRaw, dacl.AceCount.Value.(uint16))
	dacl.AceCount.RawData = aceCountRaw

	daclRaw := []byte{}
	daclRaw = append(daclRaw, dacl.Revision)
	daclRaw = append(daclRaw, dacl.Sbz1)
	daclRaw = append(daclRaw, dacl.AclSize.RawData...)
	daclRaw = append(daclRaw, dacl.AceCount.RawData...)
	daclRaw = append(daclRaw, dacl.Sbz2.RawData...)

	dacl.RawData = daclRaw
}

func aceResolve(aceData []byte, aceSize int) (*ace.AceStruct, error) {
	if aceSize == 0 || len(aceData) != aceSize {
		return nil, errors.New("The actual size of aceEntry does not match the input size")
	}

	aceEntry := ace.NewAceStruct()
	var err error

	aceEntry.AceType = aceData[0]
	aceEntry.AceFlags = aceData[1]

	aceEntry.AceSize = &datatype.DataType{RawData: aceData[2:4]}
	aceEntry.AceSize.Value, err = datatype.GetValue(aceEntry.AceSize.RawData[:])
	if err != nil {
		return nil, err
	}

	aceEntry.AceMask = &ace.AceMaskStruct{}
	aceEntry.AceMask.RawData = aceData[4:8]
	aceEntry.AceMask.Value, err = datatype.GetValue(aceEntry.AceMask.RawData[:])
	if err != nil {
		return nil, err
	}

	aceEntry.Extended = &datatype.DataType{RawData: aceData[8:12]}
	aceEntry.Extended.Value, err = datatype.GetValue(aceEntry.Extended.RawData[:])
	if err != nil {
		return nil, err
	}

	extended := 0
	size := 8
	switch int(aceEntry.Extended.Value.(uint32)) {
	case 1:
		// ObjectType
		aceEntry.ObjectType = &datatype.DataType{RawData: aceData[12:28]}
		aceEntry.ObjectType.Value, err = guid.GuidToString(aceEntry.ObjectType.RawData)
		if err != nil {
			return nil, err
		}

		extended = 20
		aceEntry.Extended.Value = "ObjectType"
	case 2:
		//InheritedObjectType
		aceEntry.InheritedObjectType = &datatype.DataType{RawData: aceData[12:28]}
		aceEntry.InheritedObjectType.Value, err = guid.GuidToString(aceEntry.InheritedObjectType.RawData)
		if err != nil {
			return nil, err
		}

		extended = 20
		aceEntry.Extended.Value = "InheritedObjectType"
	case 3:
		// ObjectType + InheritedObjectType
		aceEntry.ObjectType = &datatype.DataType{RawData: aceData[12:28]}
		aceEntry.ObjectType.Value, err = guid.GuidToString(aceEntry.ObjectType.RawData)
		if err != nil {
			return nil, err
		}

		aceEntry.InheritedObjectType = &datatype.DataType{RawData: aceData[28:44]}
		aceEntry.InheritedObjectType.Value, err = guid.GuidToString(aceEntry.InheritedObjectType.RawData)
		if err != nil {
			return nil, err
		}

		extended = 36
		aceEntry.Extended.Value = "ObjectType + InheritedObjectType"
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
		//return nil, errors.New(fmt.Sprintf("error extended type: %x\n", aceEntry.Extended.RawData))
		aceEntry.Extended.Value = "NULL"

	}

	aceEntry.SID = &datatype.DataType{RawData: aceData[size+extended:]}
	aceEntry.SID.Value = sid.SidToString(aceEntry.SID.RawData[:])

	aceEntry.RawData = aceData

	return aceEntry, nil
}

func (acl *AclHeader) initACLHeader(data []byte) error {
	if len(data) != 8 {
		fmt.Printf("AclHeader header length error")
		return errors.New("bad AclHeader header length")
	}

	var err error

	acl.Revision = data[0]
	acl.Sbz1 = data[1]

	acl.AclSize = &datatype.DataType{RawData: data[2:4]}
	acl.AclSize.Value, err = datatype.GetValue(acl.AclSize.RawData[:])
	if err != nil {
		return err
	}

	acl.AceCount = &datatype.DataType{RawData: data[4:6]}
	acl.AceCount.Value, err = datatype.GetValue(acl.AceCount.RawData[:])
	if err != nil {
		return err
	}

	acl.Sbz2 = &datatype.DataType{RawData: data[6:8]}
	acl.Sbz2.Value, err = datatype.GetValue(acl.Sbz2.RawData[:])
	if err != nil {
		return err
	}

	return nil
}
