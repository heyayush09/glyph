package logging

import (
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

var Log = logrus.New()

func init() {
	// Set the output to standard out
	Log.SetOutput(os.Stdout)

	// Set the log level from environment variable
	level, err := logrus.ParseLevel(strings.ToLower(os.Getenv("LOG_LEVEL")))
	if err != nil {
		level = logrus.InfoLevel // Default to Info level
	}
	Log.SetLevel(level)

	// Use a more structured formatter
	Log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})
}
