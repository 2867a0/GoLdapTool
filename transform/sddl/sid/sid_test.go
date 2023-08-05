package sid

import (
	"fmt"
	"goLdapTools/log"
	"testing"
)

func TestSidToString(t *testing.T) {
	testSid := []byte{
		0x01,
		0x05,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
		0x15, 0x00, 0x00, 0x00,
		0xbd, 0xc4, 0x2b, 0x21,
		0x37, 0xc7, 0x25, 0x7f,
		0xee, 0x39, 0x37, 0x47,
		0x00, 0x02, 0x00, 0x00,
		// 无用字段
		0xcc, 0xcc, 0xcc, 0xdd,
	}

	sidStr, rawData := SidToString(testSid)

	fmt.Printf("%s\n", sidStr)

	for _, v := range rawData {
		fmt.Printf("%02x, ", v)
	}
}

func TestStringToSid(t *testing.T) {
	log.Init(false)
	data, err := StringToSid("S-1-5-32-544")
	if err != nil {
		log.PrintErrorf(err.Error())
	}

	byteDataStr := fmt.Sprintf("\n0x%02x, \n0x%02x, \n", data[0], data[1])
	for _, d := range data[2:8] {
		byteDataStr += fmt.Sprintf("0x%02x, ", d)
	}
	byteDataStr += "\n"

	for i, d := range data[8:] {
		byteDataStr += fmt.Sprintf("0x%02x, ", d)
		if (i+1)%4 == 0 {
			byteDataStr += "\n"
		}
	}

	log.PrintInfof(byteDataStr)
}
