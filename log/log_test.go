package log

import "testing"

func TestLog(t *testing.T) {
	Init(true)

	PrintInfo("info test")
	PrintInfo(123)
	PrintInfof("%s\n", "infof test")

	PrintSuccess("success info")
	PrintSuccessf("%s", "successf info")

	PrintDebug("debug info")
	PrintDebugf("%s", "debugf info")

	PrintError("error info")
	PrintErrorf("%s", "errorf info")

	PrintWarning("warning info")
	PrintWarningf("%s", "warningf info")
}
