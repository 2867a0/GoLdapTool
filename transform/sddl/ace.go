package sddl

import (
	"errors"
	"fmt"
)

type ACE struct {
	AceType  byte
	AceFlags byte
	AceSize  [2]byte
}

type AceMaks struct {
	Mask [32]byte
}

func (ace ACE) readACEHeader(data []byte) error {
	if len(data) != 4 {
		fmt.Printf("ACE header length error")
		return errors.New("bad ACE header length")
	}

	ace.AceType = data[0]
	ace.AceFlags = data[1]
	ace.AceSize = [2]byte(data[2:4])

	return nil
}
