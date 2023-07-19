package sid

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

/*
https://github.com/go-ldap/ldap/issues/224
https://github.com/bwmarrin/go-objectsid
*/

type sid struct {
	RevisionLevel     int
	SubAuthorityCount int
	Authority         int
	SubAuthorities    []int
	RelativeID        *int
}

func SidToString(b []byte) string {
	var ss sid

	ss.RevisionLevel = int(b[0])
	ss.SubAuthorityCount = int(b[1]) & 0xFF

	for i := 2; i <= 7; i++ {
		ss.Authority = ss.Authority | int(b[i])<<(8*(5-(i-2)))
	}

	var offset = 8
	var size = 4
	for i := 0; i < ss.SubAuthorityCount; i++ {
		var subAuthority int
		for k := 0; k < size; k++ {
			subAuthority = subAuthority | (int(b[offset+k])&0xFF)<<(8*k)
		}
		ss.SubAuthorities = append(ss.SubAuthorities, subAuthority)
		offset += size
	}

	s := fmt.Sprintf("S-%d-%d", ss.RevisionLevel, ss.Authority)
	for _, v := range ss.SubAuthorities {
		s += fmt.Sprintf("-%d", v)
	}
	return s
}

func StringToSid(sidString string) ([]byte, error) {
	if !strings.HasPrefix(sidString, "s") && !strings.HasPrefix(sidString, "S") {
		return nil, errors.New("string is not a valid sid structure")
	}

	sidData := []byte{}
	sids := strings.Split(sidString, "-")

	revisionLevel, _ := strconv.Atoi(sids[1])
	subAuthorityCount := len(sids) - 3

	authority := []byte{0, 0}
	auth := make([]byte, 4)
	authStr, _ := strconv.Atoi(sids[2])
	binary.BigEndian.PutUint32(auth, uint32(authStr))
	authority = append(authority, auth...)

	sidData = append(sidData, byte(revisionLevel))
	sidData = append(sidData, byte(subAuthorityCount))
	sidData = append(sidData, authority...)

	for i := 3; i < len(sids); i++ {
		intData, _ := strconv.Atoi(sids[i])
		subAuthority := make([]byte, 4)
		binary.LittleEndian.PutUint32(subAuthority, uint32(intData))

		sidData = append(sidData, subAuthority...)
	}

	return sidData, nil
}
