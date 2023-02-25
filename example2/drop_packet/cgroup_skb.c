// +build ignore

#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#define bpf_printk(fmt, ...)                                    \
({                                                              \
               char ____fmt[] = fmt;                            \
               bpf_trace_printk(____fmt, sizeof(____fmt),       \
                                ##__VA_ARGS__);                 \
})

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} dest_ip_pkt_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} blocked_ip_array SEC(".maps");


/*
 *
iph 구조체
  struct iphdr
      {
   #if __BYTE_ORDER == __LITTLE_ENDIAN
        unsigned int ihl:4;            // header length 
        unsigned int version:4;        // version
   #elif __BYTE_ORDER == __BIG_ENDIAN
        unsigned int version:4;        // version
        unsigned int ihl:4;            // header length
   #else
   # error "Please fix <bits/endian.h>"// 
   #endif
        u_int8_t tos;                  // type of service
        u_int16_t tot_len;             // total length
        u_int16_t id;                  // identification
        u_int16_t frag_off;            // fragment offset field
        u_int8_t ttl;                  // time to live
        u_int8_t protocol;             // protocol
        u_int16_t check;               // checksum
        u_int32_t saddr;               // source address
        u_int32_t daddr;               // dest address
      };
 */

int handle_packet(struct __sk_buff* skb) {
    // 비즈니스 로직 구현
    struct iphdr iph;

    // 패킷 헤더 로드
    bpf_skb_load_bytes(skb, 0, &iph, sizeof(iph));

    // 디버깅용 프린트
    bpf_printk("egress ip address : %d\n", iph.daddr);

    __u64* ip_val = bpf_map_lookup_elem(&blocked_ip_array, &iph.daddr);
    if (ip_val) { // lookup에 성공했을 경우
        // blocked_ip_array 에 iph.daddr이 있을 경우 drop

        // drop된 패킷 개수 증가
        __u64 *count = bpf_map_lookup_elem(&dest_ip_pkt_count, &iph.daddr);
        if (!count) {
            // intialize step (go에서 초기화하기 전을 위한 방어코드)
            // 실제로 bpf 프로그램이 로드되고 난 후부터는 이 부분은 호출되지 않는다.
            return 1;
        }

        // drop된 패킷개수 하나 증가
        __sync_fetch_and_add(count, 1);
        return 0;
    }

    // bpf_printk("%d\n", *ip_val);
    return 1;
}

SEC("cgroup_skb/egress")
int count_egress_packets(struct __sk_buff *skb) {
    // return 1; // 1 리턴은 Allow, 0 리턴은 Deny
    return handle_packet(skb);
}

// https://patchwork.ozlabs.org/project/netdev/patch/20180528004344.3606-4-daniel@iogearbox.net/
// GPL 호환 안되면 커널 샌드박스에서 실행이 안된다
char __license[] SEC("license") = "Dual MIT/GPL";
