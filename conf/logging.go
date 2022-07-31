package conf

import (
	"os"

	"github.com/gobuffalo/pop/v5"
	"github.com/gobuffalo/pop/v5/logging"
	plog "github.com/gobuffalo/pop/v5/logging"
	"github.com/sirupsen/logrus"
)

const (
	LOG_SQL_ALL       = "all"
	LOG_SQL_NONE      = "none"
	LOG_SQL_STATEMENT = "statement"
)

type LoggingConfig struct {
	Level            string                 `mapstructure:"log_level" json:"log_level"`
	File             string                 `mapstructure:"log_file" json:"log_file"`
	DisableColors    bool                   `mapstructure:"disable_colors" split_words:"true" json:"disable_colors"`
	QuoteEmptyFields bool                   `mapstructure:"quote_empty_fields" split_words:"true" json:"quote_empty_fields"`
	TSFormat         string                 `mapstructure:"ts_format" json:"ts_format"`
	Fields           map[string]interface{} `mapstructure:"fields" json:"fields"`
	SQL              string                 `mapstructure:"sql" json:"sql"`
}

func ConfigureLogging(config *LoggingConfig) error {
	logrus.SetFormatter(&logrus.JSONFormatter{})

	// use a file if you want
	if config.File != "" {
		f, err := os.OpenFile(config.File, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0664)
		if err != nil {
			return err
		}
		logrus.SetOutput(f)
		logrus.Infof("Set output file to %s", config.File)
	}

	if config.Level != "" {
		level, err := logrus.ParseLevel(config.Level)
		if err != nil {
			return err
		}
		logrus.SetLevel(level)
		logrus.Debug("Set log level to: " + logrus.GetLevel().String())
	}

	f := logrus.Fields{}
	for k, v := range config.Fields {
		f[k] = v
	}
	logrus.WithFields(f)

	setPopLogger(config.SQL)

	return nil
}

func setPopLogger(sql string) {
	popLog := logrus.WithField("component", "pop")
	sqlLog := logrus.WithField("component", "sql")

	shouldLogSQL := sql == LOG_SQL_STATEMENT || sql == LOG_SQL_ALL
	shouldLogSQLArgs := sql == LOG_SQL_ALL

	pop.SetLogger(func(lvl plog.Level, s string, args ...interface{}) {
		// Special case SQL logging since we have 2 extra flags to check
		if lvl == logging.SQL {
			if !shouldLogSQL {
				return
			}

			if shouldLogSQLArgs && len(args) > 0 {
				sqlLog.WithField("args", args).Info(s)
			} else {
				sqlLog.Info(s)
			}
			return
		}

		l := popLog
		if len(args) > 0 {
			l = l.WithField("args", args)
		}

		switch lvl {
		case logging.Debug:
			l.Debug(s)
		case logging.Info:
			l.Info(s)
		case logging.Warn:
			l.Warn(s)
		case logging.Error:
			l.Error(s)
		}
	})
}

func conditionallyPopArgs(log *logrus.Entry, args []interface{}) *logrus.Entry {
	if len(args) == 0 {
		return log
	}
	return log.WithField("args", args)
}
