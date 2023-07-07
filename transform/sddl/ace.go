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

type AceMask struct {
	Mask [4]byte
}

type AceMaskType struct {
	Type [4]byte
}

func (ace *ACE) readACEHeader(data []byte) error {
	if len(data) != 4 {
		fmt.Printf("ACE header length error")
		return errors.New("bad ACE header length")
	}

	ace.AceType = data[0]
	ace.AceFlags = data[1]
	ace.AceSize = [2]byte(data[2:4])

	return nil
}

func (aceMask *AceMask) readACEMask(data []byte) error {
	if len(data) != 4 {
		fmt.Printf("AceMask length error")
		return errors.New("bad AceMask length")
	}
	aceMask.Mask = [4]byte(data)

	return nil
}

func (aceMaskType *AceMaskType) readACEMaskType(data []byte) error {
	if len(data) != 4 {
		fmt.Printf("AceMaskType length error")
		return errors.New("bad AceMaskType length")
	}
	aceMaskType.Type = [4]byte(data)

	return nil
}
