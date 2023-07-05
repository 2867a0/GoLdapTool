package transform

import "fmt"

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
