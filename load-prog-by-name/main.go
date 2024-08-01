package main

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/urfave/cli/v2"
)

//go:generate clang -g -target bpf -O2 -c prog.c -o prog.o

//go:embed prog.o
var ProgBytes []byte

type XDP_ACTION int

const (
	XDP_ABORTED XDP_ACTION = iota
	XDP_DROP
	XDP_PASS
	XDP_TX
	XDP_REDIRECT
)

type Datarec struct {
	RxPkts  uint64
	RxBytes uint64
}

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

	statsMap := coll.Maps["xdp_stats_map"]
	if statsMap == nil {
		return errors.New("xdp_stats_map not exist")
	}

	// Waiting for exit
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	tick := time.Tick(time.Second)

	for {
		select {
		case sig := <-stop:
			fmt.Printf("Receive %s, exist..", sig)
			return nil
		case <-tick:
			var passDr Datarec
			if err := statsMap.Lookup(uint32(XDP_PASS), &passDr); err != nil {
				return err
			}

			var dropDr Datarec
			if err := statsMap.Lookup(uint32(XDP_DROP), &dropDr); err != nil {
				return err
			}

			fmt.Printf("====================\nstats\npass: %+v\ndrop: %+v\n", passDr, dropDr)
		}
	}
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
