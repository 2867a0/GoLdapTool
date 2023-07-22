package main

import (
	"goLdapTools/cli"
	"goLdapTools/log"
)

func init() {
	log.Init(log.Release)
}

func main() {
	cli.Execute()
}
