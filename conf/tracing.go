package conf

type TracingConfig struct {
	Enabled     bool `default:"false"`
	Host        string
	Port        string
	ServiceName string `default:"gotrue" split_words:"true"`
	Tags        map[string]string
}

func (tc *TracingConfig) Validate() error {
	return nil
}
