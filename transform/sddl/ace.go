package sddl

import "fmt"

// AceType Flag
const (
	ACCESS_ALLOWED_ACE_TYPE                 = 0x00
	ACCESS_DENIED_ACE_TYPE                  = 0x01
	SYSTEM_AUDIT_ACE_TYPE                   = 0x02
	SYSTEM_ALARM_ACE_TYPE                   = 0x03
	ACCESS_ALLOWED_COMPOUND_ACE_TYPE        = 0x04
	ACCESS_ALLOWED_OBJECT_ACE_TYPE          = 0x05
	ACCESS_DENIED_OBJECT_ACE_TYPE           = 0x06
	SYSTEM_AUDIT_OBJECT_ACE_TYPE            = 0x07
	SYSTEM_ALARM_OBJECT_ACE_TYPE            = 0x08
	ACCESS_ALLOWED_CALLBACK_ACE_TYPE        = 0x09
	ACCESS_DENIED_CALLBACK_ACE_TYPE         = 0x0A
	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B
	ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  = 0x0C
	SYSTEM_AUDIT_CALLBACK_ACE_TYPE          = 0x0D
	SYSTEM_ALARM_CALLBACK_ACE_TYPE          = 0x0E
	SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   = 0x0F
	SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   = 0x10
	SYSTEM_MANDATORY_LABEL_ACE_TYPE         = 0x11
	SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE      = 0x12
	SYSTEM_SCOPED_POLICY_ID_ACE_TYPE        = 0x13
)

// AceFlags Flag
const (
	CONTAINER_INHERIT_ACE      = 0x02
	FAILED_ACCESS_ACE_FLAG     = 0x80
	INHERIT_ONLY_ACE           = 0x08
	INHERITED_ACE              = 0x10
	NO_PROPAGATE_INHERIT_ACE   = 0x04
	OBJECT_INHERIT_ACE         = 0x01
	SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
)

// ace mask flags
const (
	GENERIC_READ           = 0x80000000
	GENERIC_WRITE          = 0x40000000
	GENERIC_EXECUTE        = 0x20000000
	GENERIC_ALL            = 0x10000000
	MAXIMUM_ALLOWED        = 0x02000000
	ACCESS_SYSTEM_SECURITY = 0x01000000
	SYNCHRONIZE            = 0x00100000
	WRITE_OWNER            = 0x00080000
	WRITE_DACL             = 0x00040000
	READ_CONTROL           = 0x00020000
	DELETE                 = 0x00010000
)

// AceMaskMap ace mask flags
var AceMaskMap = map[string]uint32{
	"GENERIC_READ":           0x80000000,
	"GENERIC_WRITE":          0x40000000,
	"GENERIC_EXECUTE":        0x20000000,
	"GENERIC_ALL":            0x10000000,
	"MAXIMUM_ALLOWED":        0x02000000,
	"ACCESS_SYSTEM_SECURITY": 0x01000000,
	"SYNCHRONIZE":            0x00100000,
	"WRITE_OWNER":            0x00080000,
	"WRITE_DACL":             0x00040000,
	"READ_CONTROL":           0x00020000,
	"DELETE":                 0x00010000,
}

type AceMaskStruct struct {
	DataType
}

type AceStruct struct {
	AceType  byte
	AceFlags byte
	AceSize  *DataType
	// 4 Bits
	AceMask  *AceMaskStruct //TODO resolve data to string
	Extended *DataType
	// 16 Bits
	ObjectType *DataType
	// 16 Bits
	InheritedObjectType *DataType
	SID                 *DataType
}

func (aceMask *AceMaskStruct) HasPriv(priv uint32) (bool, error) {
	data, err := getValue(aceMask.RawData)
	if err != nil {
		return false, err
	}

	return data&priv == priv, nil
}

func (aceMask *AceMaskStruct) setPriv(priv uint32) {
	aceMask.Value = aceMask.Value.(uint32) | priv
}

// TODO 字段错误
func (aceMask *AceMaskStruct) getAceMaskString() (string, error) {
	var privStr string
	for k, v := range AceMaskMap {
		hasPriv, err := aceMask.HasPriv(v)
		if err != nil {
			return "", err
		}

		if hasPriv {
			privStr += fmt.Sprintf("%s;", k)
		}
	}

	return privStr, nil
}
