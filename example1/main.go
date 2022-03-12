//go:build linux
// +build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	// "github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go  -cflags "-O2  -g -Wall -Werror -I./headers"  bpf hello.c

// Length of struct event_t sent from kernelspace.
var eventLength = 12

type Event struct {
	SPort uint16
	DPort uint16
	SAddr uint32
	DAddr uint32
}

type TestEvent struct {
	Count uint16
}

// UnmarshalBinary unmarshals a ringbuf record into an Event.
func (e *Event) UnmarshalBinary(b []byte) error {
	if len(b) != eventLength {
		return fmt.Errorf("unexpected event length %d", len(b))
	}

	e.SPort = binary.BigEndian.Uint16(b[0:2])
	e.DPort = binary.BigEndian.Uint16(b[2:4])

	e.SAddr = binary.BigEndian.Uint32(b[4:8])
	e.DAddr = binary.BigEndian.Uint32(b[8:12])

	return nil
}

func (e *TestEvent) Unmarshal(b []byte) error {
	if len(b) != 4 {
		return fmt.Errorf("unexpected event length %d", len(b))
	}

	e.Count = binary.BigEndian.Uint16(b[0:2]) // uint16 -> 2 byte

	return nil
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}

func main() {
	/*
		var ifaceName string
		flag.StringVar(&ifaceName, "iface", "eth0", "Interface name to attach XDP program")
		flag.Parse()

		if ifaceName == "" {
			log.Fatal("Missing required param iface")
			os.Exit(1)
		}

		stopper := make(chan os.Signal, 1)
		signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

		ifaces, err := net.Interfaces()
		if err != nil {
			log.Print(fmt.Errorf("Unable to get list of interfaces: %+v\n", err.Error()))
			return
		}
	*/

	// Allow the current process to lock memory for eBPF resources.
	/*
		if err := rlimit.RemoveMemlock(); err != nil {
			log.Fatal(err)
		}
	*/

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// group, name은 SEC() <- 에서 주어지는 이름을 쓰면 됨. 아래의 경우에는 tracepoint/syscalls/sys_enter_execve 니까 아래처럼 쓴 것.
	trace, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.BpfProg)

	if err != nil {
		log.Fatalf("Failed to open tracepoint: %s", err)
	}
	defer trace.Close()

	// XDP
	/*
		var xdpIface net.Interface
		var foundIface bool
		for _, iface := range ifaces {
			if iface.Name == ifaceName {
				xdpIface = iface
				foundIface = true
			}
		}
		if !foundIface {
			log.Fatalf("Unable to find given interface")
		}

		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpSampleProg,
			Interface: xdpIface.Index,
		})
		defer l.Close()
		if err != nil {
			log.Fatalf("attaching xdp: %s", err)
		}
	*/

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map
	// described in the eBPF C program.
	rd, err := perf.NewReader(objs.EventsPerfEventArray, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	var event TestEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		err = event.Unmarshal(record.RawSample)
		if err != nil {
			log.Println("parse error", err)
		}

		log.Printf("Read from perf event unmarshal: %d", event.Count)

		const key uint32 = 0
		var value uint64
		if err = objs.CountingMap.Lookup(key, &value); err != nil {
			log.Fatal(err)
		}

		log.Printf("Read from golang lookup: %d", value)

		// log.Printf("New connection: %s:%d -> %s:%d \n", intToIP(event.SAddr).String(), event.SPort, intToIP(event.DAddr).String(), event.DPort)
	}
}
