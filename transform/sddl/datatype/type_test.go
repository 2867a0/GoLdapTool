package datatype

import (
	"fmt"
	"goLdapTools/log"
	"goLdapTools/transform/sddl/guid"
	"testing"
)

func TestGuidToString(t *testing.T) {
	data := []byte{
		0x00, 0x42, 0x16, 0x4c, 0xc0, 0x20, 0xd0, 0x11, 0xa7, 0x68, 0x00, 0xaa, 0x00, 0x6e, 0x05, 0x29,
	}

	toString, err := guid.GuidToString(data)
	if err != nil {
		fmt.Printf(err.Error())
	}
	fmt.Printf("%s\n", toString)
}

func TestStringToGUID(t *testing.T) {
	log.Init(false)
	guidString := "4C164200-20C0-11D0-A768-00AA006E0529"

	data, err := guid.StringToGuid(guidString)
	if err != nil {
		log.PrintErrorf(err.Error())
	}

	dataString := ""
	for _, d := range data {
		dataString += fmt.Sprintf("0x%02x, ", d)
	}
	log.PrintInfof(dataString)
}
