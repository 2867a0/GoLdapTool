package transform

import (
	"fmt"
	"testing"
)

func TestTimeToString(t *testing.T) {
	v, err := TimeToString("133344647757423366")
	if err != nil {
		fmt.Printf("error: %s", err.Error())
		return
	}
	fmt.Printf(v)
}
