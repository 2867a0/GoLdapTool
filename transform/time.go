package transform

import (
	"strconv"
	"strings"
	"time"
)

func TimeToString(data string) (string, error) {
	if strings.EqualFold(data, "0") {
		return "Null", nil
	}

	tInt, err := strconv.Atoi(data)
	if err != nil {
		return "", err
	}

	dataInt := (tInt / 10000000) - 11644473600

	tm := time.Unix(int64(dataInt), 0)
	return tm.String(), nil
}
