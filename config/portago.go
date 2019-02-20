// config for portago server
// read file from first arg

package config

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"os"
)

type conf = struct{
	Server server
}
type server = struct {
	Port int
}

var Conf conf

func init() {
	// default
	switch len(os.Args) {
	case 1:
		// default conf
	case 2:
		_, err := toml.DecodeFile(os.Args[1], &Conf)
		if err != nil {
			println(err.Error())
			panic(err)
		}
		fmt.Printf("%+v\n", Conf)
	default:
		panic("too many args")
	}
}
