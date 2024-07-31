package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/urfave/cli/v2"
)

//go:generate clang -target bpf -c prog.c -o prog.o

//go:embed prog.o
var ProgBytes []byte

func LoadBPFProg(cCtx *cli.Context) error {
	// Remove resource limit
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// Load spec
	r := bytes.NewReader(ProgBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(r)
	if err != nil {
		return err
	}

	// New collection
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}
	defer coll.Close()

	// Attach to iface
	iface, err := net.InterfaceByName(cCtx.String("iface"))
	if err != nil {
		return err
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs[cCtx.String("prog")],
		Interface: iface.Index,
	})
	if err != nil {
		return err
	}
	defer link.Close()

	// Waiting for exit
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	sig := <-stop
	fmt.Printf("Receive %s, exist..", sig)
	return nil
}

func main() {
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "iface",
				Aliases:  []string{"i"},
				Usage:    "interface name that eBPF program attached on",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "prog",
				Aliases:  []string{"p"},
				Usage:    "attached eBPF program name",
				Required: true,
			},
		},
		Action: LoadBPFProg,
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
