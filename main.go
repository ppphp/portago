package main

import (
	_ "github.com/ppphp/portago/atom"
	"github.com/ppphp/portago/config"
	_ "github.com/ppphp/portago/log"
)

func main() {
	config.Read()

	//if err := api.App.Run(fmt.Sprintf(":%v", config.Conf.Server.Port)); err != nil {
	//	println(err.Error())
	//	return
	//}
}
