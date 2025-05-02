package main

import (
	"os"

	"github.com/jumpyappara/preq/cmd/plugin/krew"
	"github.com/jumpyappara/preq/internal/pkg/sigs"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

func main() {

	ctx := sigs.InitSignals()

	streams := genericclioptions.IOStreams{
		In:     os.Stdin,
		Out:    os.Stdout,
		ErrOut: os.Stderr,
	}

	krew.InitAndExecute(ctx, streams)
}
