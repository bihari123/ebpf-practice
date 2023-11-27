#!/usr/bin/python
from bcc import BPF

program = r"""
BPF_PERF_OUTPUT(output);
struct data_t {
    int pid;
    int uid;
    char command[16];
    char message[12];
    char filepath[256];
};

int file_opened(void *ctx) {
    struct data_t data = {};
    char message[12] = "File Opened";
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.command, sizeof(data.command));

    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);


    output.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
int file_write(void *ctx) {
    struct data_t data = {};
    char message[12] = "File Written";
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    bpf_get_current_comm(&data.command, sizeof(data.command));

    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);

    output.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
int file_close(void *ctx) {
    struct data_t data = {};
    char message[12] = "File Closed";
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    bpf_get_current_comm(&data.command, sizeof(data.command));

    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);

    output.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

"""


b = BPF(text=program)
file_open_syscall = b.get_syscall_fnname("openat")
file_write_syscall = b.get_syscall_fnname("write")
file_close_syscall = b.get_syscall_fnname("close")

b.attach_kprobe(event=file_open_syscall, fn_name="file_opened")
b.attach_kprobe(event=file_write_syscall, fn_name="file_write")
b.attach_kprobe(event=file_write_syscall, fn_name="file_close")

def print_event(cpu, data, size):
    data = b["output"].event(data)
    if data.command.decode() == 'nvim':
      print(f"process id: {data.pid}, userId: {data.uid} command: {data.command.decode()} message: " + \
      f"{data.message.decode()}")
    else:
        return


b["output"].open_perf_buffer(print_event)


while True:
    b.perf_buffer_poll()



