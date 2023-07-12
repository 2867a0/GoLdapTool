package sddl

import "fmt"

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

// AceMaskBitMap ace mask flags
var AceMaskBitMap = map[string]uint32{
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

func (aceMask *AceMaskStruct) getAceMaskString() (string, error) {
	var privStr string
	for k, v := range AceMaskBitMap {
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
