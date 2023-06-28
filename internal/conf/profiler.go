package conf

type ProfilerConfig struct {
	Enabled bool   `default:"false"`
	Addr    string `default:"localhost:9998"`
}
