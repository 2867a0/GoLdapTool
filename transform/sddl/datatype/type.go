package datatype

import (
	"errors"
)

type DataType struct {
	RawData []byte
	Value   interface{}
}

// GetValue (2/4)字节数据转换为小端结构数据(uint16/uint32)
func GetValue(data []byte) (interface{}, error) {
	var value interface{}
	if len(data) == 2 {
		value = uint16(data[0]) | uint16(data[1])<<8
	} else if len(data) == 4 {
		value = uint32(int(uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24))
	} else {
		return 0, errors.New("unable to parse byte length")
	}

	return value, nil
}
