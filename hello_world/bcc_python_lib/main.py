#!/usr/bin/python
from bcc import BPF
# The eBPF program itself is written in C code, and it’s this part:
program = r"""
int hello(void *ctx) {
bpf_trace_printk("Hello World!");
return 0;
}
"""

# The entire eBPF program is defined as a string called program in the Python code.
# This C program needs to be compiled before it can be executed, but BCC takes care
# of that for you. (You’ll see how to compile eBPF programs yourself in the next chap‐
# ter.) All you need to do is pass this string as a parameter when creating a BPF object,
# as in the following line:

b = BPF(text=program)

# eBPF programs need to be attached to an event, and for this example I’ve chosen to
# attach to the system call execve, which is the syscall used to execute a program.
# Whenever anything or anyone starts a new program executing on this machine, that
# will call execve(), which will trigger the eBPF program. Although the “execve()”
# name is a standard interface in Linux, the name of the function that implements it in
# the kernel depends on the chip architecture, but BCC gives us a convenient way to
# look up the function name for the machine we’re running on:
syscall = b.get_syscall_fnname("execve")

# Now, syscall represents the name of the kernel function I’m going to attach to, using
# a kprobe  You can
# attach the hello function to that event, like this:

b.attach_kprobe(event=syscall, fn_name="hello")

# At this point, the eBPF program is loaded into the kernel and attached to an event, so
# the program will be triggered whenever a new executable gets launched on the
# machine. All that’s left to do in the Python code is to read the tracing that is output by
# the kernel and write it on the screen:

b.trace_print()
