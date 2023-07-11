package sddl

import (
	"errors"
	"fmt"
)

type DataType struct {
	RawData []byte
	Value   interface{}
}

func getValue(data []byte) (uint32, error) {
	var value uint32
	if len(data) == 2 {
		value = uint32(int(uint16(data[0]) | uint16(data[1])<<8))
	} else if len(data) == 4 {
		value = uint32(int(uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24))
	} else {
		return 0, errors.New("unable to parse byte length")
	}

	return value, nil
}

func GuidToString(data []byte) (string, error) {
	var guidString string
	if len(data) != 16 {
		return guidString, errors.New("the incoming data length is not a valid GUID data format length")
	}

	//4
	guid1 := data[0:4]
	for i := range guid1 {
		guidString += fmt.Sprintf("%02X", guid1[len(guid1)-i-1])
	}

	//2-2
	guidString += fmt.Sprintf("-%02X%02X-%02X%02X-", data[5], data[4], data[7], data[6])

	// 2
	guidString += fmt.Sprintf("%02X%02x-", data[8], data[9])

	//6
	guid2 := data[10:]
	for i := range guid2 {
		guidString += fmt.Sprintf("%02X", guid2[i])
	}

	return guidString, nil
}
