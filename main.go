package main

import (
	"flag"
	"github.com/jingyanbin/core/log"
	"rdx/rd"
)

func main() {
	runMode := flag.String("mode", "rda", "run mode")
	flag.Parse()
	defer log.Close()
	if *runMode == "rds" {
		rds := rd.Rds{}
		rds.Start()
	} else if *runMode == "rdc" {
		rdc := rd.Rdc{}
		rdc.Start()
	} else {
		rdc := rd.Rda{}
		rdc.Start()
	}
	return
}
