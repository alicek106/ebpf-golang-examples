// cilium의 ebpf 파일에서 옮겨옴 (ebpf/examples/cgroup_skb)
// examples를 그대로 쓰면 2022/03/12 04:55:00 loading objects: field CountEgressPackets: program count_egress_packets: can't load BigEndian program on LittleEndian 에러가 발생
// 직접 object 파일을 load해서 쓰면 됨.
package main

import (
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func intToIP(val uint32) net.IP {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], val)
	return net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3])
}

func ipToInt(val string) uint32 {
	ip := net.ParseIP(val).To4()
	return binary.LittleEndian.Uint32(ip)
}

func main() {
	collec, err := ebpf.LoadCollection("./cgroup_skb.o")
	if err != nil {
		log.Fatal(err)
	}

	/*
		BPF only supports attaching programs to v2 cgroups. 라고 한다. cgroupfs에서는 사용불가
		cgroup v2 활성화하는 방법
		https://sleeplessbeastie.eu/2021/09/10/how-to-enable-control-group-v2/
	*/

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

	bpf_map := collec.Maps["dest_ip_pkt_count"]
	block_ip_map := collec.Maps["blocked_ip_array"]

	ip := ipToInt("8.8.8.8")
	block_ip_map.Put(&ip, uint32(0))
	bpf_map.Put(&ip, uint64(0)) // hashMap에 먼저 값을 pre-define 한다. array에도 똑같이 put 가능

	log.Println("Starting..")

	ticker := time.NewTicker(1 * time.Second)

	for range ticker.C {
		var value uint64
		if err := bpf_map.Lookup(&ip, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("number of packets: %d\n", value)
	}
}
