package log

import (
	"fmt"
	"os"

	"github.com/gookit/color"
	"github.com/gookit/slog"
)

var std = &slog.SugaredLogger{}
var template string

var infoPrefix = "➰"
var successPrefix = "✔"
var debugPrefix = "♻"
var errorPrefix = "❌"
var warningPrefix = "❗"

var SaveResultStr = ""

func Init(isRelease bool) {
	if !isRelease {
		template = "[{{datetime}}] [{{level}}] {{message}} {{data}} {{extra}}\n"
		std = newStdLogger(slog.DebugLevel)
		PrintDebug("debug mode is on")
	} else {
		template = "{{message}} {{data}} {{extra}}\n"
		std = newStdLogger(slog.InfoLevel)
	}
}

// NewStdLogger instance
func newStdLogger(level slog.Level) *slog.SugaredLogger {
	return slog.NewSugaredLogger(os.Stdout, level).Configure(func(sl *slog.SugaredLogger) {
		sl.SetName("stdLogger")
		sl.ReportCaller = true
		sl.CallerSkip = 3
		// auto enable console color
		sl.Formatter.(*slog.TextFormatter).EnableColor = color.SupportColor()
		sl.Formatter.(*slog.TextFormatter).SetTemplate(template)
	})
}

// PrintInfo logs a message at level Info
func PrintInfo(args ...interface{}) {
	var aargs1 []interface{}
	aargs1 = append(aargs1, infoPrefix, " ")
	aargs1 = append(aargs1, args...)

	std.Log(slog.InfoLevel, aargs1...)
}

// PrintInfof logs a message at level Info
func PrintInfof(format string, args ...interface{}) {
	formats := fmt.Sprintf("%s %s", infoPrefix, format)
	std.Logf(slog.InfoLevel, formats, args...)
}

func PrintSuccess(args ...interface{}) {
	var aargs1 []interface{}
	aargs1 = append(aargs1, successPrefix)
	aargs1 = append(aargs1, args...)

	std.Log(slog.InfoLevel, aargs1...)
}

func PrintSuccessf(format string, args ...interface{}) {
	formats := fmt.Sprintf("%s %s", successPrefix, format)
	std.Logf(slog.InfoLevel, formats, args...)
}

// PrintDebug logs a message at level Debug
func PrintDebug(args ...interface{}) {
	var aargs1 []interface{}
	aargs1 = append(aargs1, debugPrefix)
	aargs1 = append(aargs1, args...)

	std.Log(slog.DebugLevel, aargs1...)
}

// PrintDebugf logs a message at level Debug
func PrintDebugf(format string, args ...interface{}) {
	formats := fmt.Sprintf("%s %s", debugPrefix, format)
	std.Logf(slog.DebugLevel, formats, args...)
}

// PrintError logs a message at level Debug
func PrintError(args ...interface{}) {
	var aargs1 []interface{}
	aargs1 = append(aargs1, errorPrefix)
	aargs1 = append(aargs1, args...)

	std.Log(slog.ErrorLevel, aargs1...)
}

// PrintErrorf logs a message at level Debug
func PrintErrorf(format string, args ...interface{}) {
	formats := fmt.Sprintf("%s %s", errorPrefix, format)
	std.Logf(slog.ErrorLevel, formats, args...)
}

// PrintWarning logs a message at level Debug
func PrintWarning(args ...interface{}) {
	var aargs1 []interface{}
	aargs1 = append(aargs1, warningPrefix)
	aargs1 = append(aargs1, args...)

	std.Log(slog.WarnLevel, aargs1...)
}

// PrintWarningf logs a message at level Debug
func PrintWarningf(format string, args ...interface{}) {
	formats := fmt.Sprintf("%s %s", warningPrefix, format)
	std.Logf(slog.WarnLevel, formats, args...)
}
