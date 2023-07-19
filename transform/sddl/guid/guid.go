package guid

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

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

func StringToGuid(guidString string) ([]byte, error) {
	g := strings.Split(guidString, "-")
	if len(g) != 5 {
		return nil, errors.New("invalid guid format")
	}

	guidBytes := []byte{}

	// 小端 4
	guid_1, err := guidTrans(g[0], "l")
	if err != nil {
		return nil, err
	}
	guidBytes = append(guidBytes, guid_1...)

	// 小端 2
	guid_2, err := guidTrans(g[1], "l")
	if err != nil {
		return nil, err
	}
	guidBytes = append(guidBytes, guid_2...)

	// 小端 2
	guid_3, err := guidTrans(g[2], "l")
	if err != nil {
		return nil, err
	}
	guidBytes = append(guidBytes, guid_3...)

	// 大端 2
	guid_4, err := guidTrans(g[3], "b")
	if err != nil {
		return nil, err
	}
	guidBytes = append(guidBytes, guid_4...)

	// 大端 6
	guid_5, err := guidTrans(g[4], "b")
	if err != nil {
		return nil, err
	}
	guidBytes = append(guidBytes, guid_5...)

	return guidBytes, nil
}

func guidTrans(g string, l string) ([]byte, error) {
	var data []byte

	if l == "l" {
		for i := 0; i < len(g); i += 2 {
			value, err := strconv.ParseInt(g[i:i+2], 16, 0)
			if err != nil {
				return nil, err
			}
			lData := []byte{byte(value)}
			lData = append(lData, data...)

			data = lData
		}
	} else {
		for i := 0; i < len(g); i += 2 {
			value, err := strconv.ParseInt(g[i:i+2], 16, 0)
			if err != nil {
				return nil, err
			}
			data = append(data, byte(value))
		}
	}

	return data, nil
}
