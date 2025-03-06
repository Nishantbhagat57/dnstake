package main

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/Nishantbhagat57/dnstake/internal/option"
	"github.com/Nishantbhagat57/dnstake/internal/runner"
)

func init() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
}

func main() {
	opt := option.Parse()

	if opt.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}

	if err := runner.New(opt); err != nil {
		gologger.Fatal().Msg(err.Error())
	}
}
