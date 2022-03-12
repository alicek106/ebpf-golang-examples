#include <linux/bpf.h>
#include <bpf_helpers.h>

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    // __uint(max_entries, 1);
	// __uint(key_size, sizeof(int));
	// __uint(value_size, 4);
} events_perf_event_array SEC(".maps");

/*
struct bpf_map_def SEC("maps") counting_map = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u64),
    .max_entries = 1,
};
*/

// 이렇게 쓰는것과 위처럼 쓰는 것은 동일하다
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u64));
} counting_map SEC(".maps");

// execve 커널 함수의 인자
struct execve_args {
    short common_type;
    char common_flags;
    char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    char *filename;
    const char *const *argv;
    const char *const *envp;
};

// https://stackoverflow.com/questions/67188440/ebpf-cannot-read-argv-and-envp-from-tracepoint-sys-enter-execve
SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(struct execve_args *ctx) {
    struct event_t {
        __u16 count;
    } __packed;


    struct event_t test_data;
    char msg[] = "Hello, BPF World!";
    bpf_trace_printk(msg, sizeof(msg));

/*
    __u32 key = 0;
    __u64 val = 1, *valp;

    valp = bpf_map_lookup_elem(&counting_map, &key);

    if (!valp) {
        bpf_map_update_elem(&counting_map, &key, &val, BPF_ANY);
    }
    __sync_fetch_and_add(valp, 1);
*/

    __u32 key     = 0;
    __u64 initval = 1, *valp;

    valp = bpf_map_lookup_elem(&counting_map, &key);
    if (!valp) {
        bpf_map_update_elem(&counting_map, &key, &initval, BPF_ANY);
        __builtin_memset(&test_data, 0, sizeof(struct event_t));
        return 0;
    } else {
        // 분명히 printk는 한번만 찍힐텐데, 왜 __sync_fetch_and_add는 수백번 반복해서 호출되는걸까?
        __sync_fetch_and_add(valp, 1);
        __builtin_memset(&test_data, *valp, sizeof(struct event_t));
    }

    int ret = bpf_perf_event_output(ctx, &events_perf_event_array, BPF_F_CURRENT_CPU, &test_data, sizeof(struct event_t));
    bpf_printk("test: %s\n", ctx->filename);
	if (ret) {
        bpf_printk("perf_event_output failed: %d\n", ret);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
