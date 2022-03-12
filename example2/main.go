// cilium의 ebpf 파일에서 옮겨옴 (ebpf/examples/cgroup_skb)
// examples를 그대로 쓰면 2022/03/12 04:55:00 loading objects: field CountEgressPackets: program count_egress_packets: can't load BigEndian program on LittleEndian 에러가 발생
// 직접 object 파일을 load해서 쓰면 됨.
package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	collec, err := ebpf.LoadCollection("./cgroup_skb.o")
	if err != nil {
		log.Fatal(err)
	}

	bpf_map := collec.Maps["pkt_count"]

	// Get the first-mounted cgroupv2 path.
	// 여기에 적절한 cgroup path를 입력한다.
	// 아래의 예시는 docker가 자동으로 생성해주는 Path를 직접 하드코딩해 보았음.
	cgroupPath := "/sys/fs/cgroup/system.slice/docker-46710b634c627e6a0a284d1f6fbf3d54aba9859e5c861f6ac14a8676cc6e5304.scope"

	// Link the count_egress_packets program to the cgroup.
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: collec.Programs["count_egress_packets"],
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	log.Println("Counting packets...")

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)

	for range ticker.C {
		var value uint64
		if err := bpf_map.Lookup(uint32(0), &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("number of packets: %d\n", value)
	}
}
