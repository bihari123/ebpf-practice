#!/usr/bin/python
from time import sleep
from bcc import BPF
# BPF_HASH() is a BCC macro that defines a hash table map
# bpf_get_current_uid_gid() is a helper function used to obtain the user ID that
# is running the process that triggered this kprobe event. The user ID is held in the
# lowest 32 bits of the 64-bit value that gets returned. (The top 32 bits hold the
# group ID, but that part is masked out.)

# Look for an entry in the hash table with a key matching the user ID. It returns a
# pointer to the corresponding value in the hash table.

# If there is an entry for this user ID, set the counter variable to the current value
# in the hash table (pointed to by p). If there is no entry for this user ID in the hash
# table, the pointer will be 0, and the counter value will be left at 0.

# Whatever the current counter value is, it gets incremented by one.

# Update the hash table with the new counter value for this user ID.

program = r"""
BPF_HASH(counter_table);
int count_syscall(void *ctx) {
u64 uid;
u64 counter = 0;
u64 *p;
uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
p = counter_table.lookup(&uid);
if (p != 0) {
  counter = *p;
  }
counter++;
counter_table.update(&uid, &counter);
return 0;
}
"""


b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")

b.attach_kprobe(event=syscall, fn_name="count_syscall")

while True:
  sleep(2)
  s = ""
  for k,v in b["counter_table"].items():
    s += f"ID {k.value}: {v.value}\t"
    print(s) 
