package main

import (
	"github.com/ppphp/portago/config"
	_ "github.com/ppphp/portago/log"
	_ "github.com/ppphp/portago/atom"
)

func main() {
	config.Read()

	//if err := api.App.Run(fmt.Sprintf(":%v", config.Conf.Server.Port)); err != nil {
	//	println(err.Error())
	//	return
	//}
}
