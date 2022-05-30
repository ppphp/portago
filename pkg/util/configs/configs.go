package configs

import (
	"github.com/ppphp/configparser"
	"os"
)

func ReadConfigs(parser configparser.ConfigParser, paths []string) error {
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		defer f.Close()
		if err := parser.ReadFile(f, p); err != nil {
			return err
		}
	}
	return nil
}
