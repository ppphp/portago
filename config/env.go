package config

type EnvSetting struct {
	config_root string
	target_root string
	sysroot     string
	eprefix     string
	Env         map[string]string
}

func Env() {

}
