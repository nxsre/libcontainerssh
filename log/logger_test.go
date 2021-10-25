package log_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/containerssh/containerssh/config"
	"github.com/containerssh/containerssh/message"
	"github.com/stretchr/testify/assert"

	"github.com/containerssh/containerssh/log"
)

func TestLogLevelFiltering(t *testing.T) {
	for logLevelInt := 0; logLevelInt < 8; logLevelInt++ {
		t.Run(fmt.Sprintf("filter=%s", config.LogLevel(logLevelInt).MustName()), func(t *testing.T) {
			for writeLogLevelInt := 0; writeLogLevelInt < 8; writeLogLevelInt++ {
				logLevel := config.LogLevel(logLevelInt)
				writeLogLevel := config.LogLevel(writeLogLevelInt)
				t.Run(
					fmt.Sprintf("write=%s", config.LogLevel(writeLogLevelInt).MustName()),
					func(t *testing.T) {
						testLevel(t, logLevel, writeLogLevel)
					},
				)
			}
		})
	}
}

func testLevel(t *testing.T, logLevel config.LogLevel, writeLogLevel config.LogLevel) {
	var buf bytes.Buffer
	p := log.MustNewLogger(config.LogConfig{
		Level:       logLevel,
		Format:      config.LogFormatLJSON,
		Destination: config.LogDestinationStdout,
		Stdout:      &buf,
	})
	message := message.UserMessage("E_TEST", "test", "test")
	switch writeLogLevel {
	case config.LogLevelDebug:
		p.Debug(message)
	case config.LogLevelInfo:
		p.Info(message)
	case config.LogLevelNotice:
		p.Notice(message)
	case config.LogLevelWarning:
		p.Warning(message)
	case config.LogLevelError:
		p.Error(message)
	case config.LogLevelCritical:
		p.Critical(message)
	case config.LogLevelAlert:
		p.Alert(message)
	case config.LogLevelEmergency:
		p.Emergency(message)
	}
	if logLevel < writeLogLevel {
		assert.Equal(t, 0, buf.Len())
	} else {
		assert.NotEqual(t, 0, buf.Len())

		rawData := buf.Bytes()
		data := map[string]interface{}{}
		if err := json.Unmarshal(rawData, &data); err != nil {
			assert.Fail(t, "failed to unmarshal JSON from writer", err)
		}

		expectedLevel := writeLogLevel.String()
		assert.Equal(t, string(expectedLevel), data["level"])
		assert.Equal(t, "test", data["message"])
	}
}