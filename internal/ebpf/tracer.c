#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_FUNCTIONS_NUMBER	 2048
#define MAX_FUNCTION_NAME_LENGTH 128

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u32 desired_pid;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_FUNCTIONS_NUMBER);
	__type(key, __u64);
	__type(value, char[MAX_FUNCTION_NAME_LENGTH]);
	// __uint(map_flags, BPF_F_RDONLY_PROG);
} function_address_to_name SEC(".maps");

struct FunctionData {
	__u32 pid;
	__u32 tid;
	__u64 addr;
	char functionName[MAX_FUNCTION_NAME_LENGTH] ;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 16); // size in bytes
	__type(value, struct FunctionData);
} function_data_rb SEC(".maps");


// used for debug
static int print_pairs(struct bpf_map *map, __u64 *key, char *val, void *ctx)
{
	if (!key || !val)
		return 0;

	// output to /sys/kernel/debug/tracing/trace_pipe
	bpf_printk("Addr: 0x%llx -> Name: %s\n", *key, val);

	return 0;
}

SEC("uprobe.multi")
int BPF_UPROBE(my_handler)
{
	struct FunctionData *function_data;

	// a bit confusing, tgid represent the shared 'main' pid, pid is different for each thread
	__u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid & 0xFFFFFFFF;
    __u32 tgid = pid_tgid >> 32;

	if (tgid != desired_pid) 
		return 0;
    
	__u64 addr = bpf_get_func_ip(ctx);

	// bpf_for_each_map_elem(&function_address_to_name, print_pairs, NULL, 0);


	function_data = bpf_ringbuf_reserve(&function_data_rb, sizeof(struct FunctionData), 0);
	if(!function_data) {
		bpf_printk("bpf_ringbuf_reserve on function_data_rb failed\n");
		return 1;
	}

	//this is not a mistake, see pid/tgid defention above
	function_data->pid = tgid;
	function_data->tid = pid;

	function_data->addr = addr;
	
	char *function_name = bpf_map_lookup_elem(&function_address_to_name, &addr);
	if (!function_name) {
		bpf_printk("error getting function name at address %d\n", addr);
		bpf_ringbuf_discard(function_data, 0);
		return 1;
	}
	bpf_probe_read_kernel_str(function_data->functionName, MAX_FUNCTION_NAME_LENGTH, function_name);

	bpf_printk("function %s called from {TGID %d, PID %d} at address 0x%x.\n", function_name, tgid, pid, addr);
	bpf_ringbuf_submit(function_data, 0);

	return 0;
}
