# ipftrace2 Internals

In this document, we'll describe how each of the `ifptrace2` features implemented.

## ipftrace2 tracing method

What `ipftrace2` does in a nut shell is **finds the kernel functions which takes `struct sk_buff *` as an argument, attach BPF program to all of them, and record the function calls**. This section describes how we implement it.

### Finding target functions

`ipftrace2` finds the target functions from BTF (BPF Type Format) type information. To maximize the tracing coverage, it tries to scan both vmlinux BTF and module BTFs. `ipftrace2` uses libbpf's `btf__load_vmlinux_btf` to find vmlinux BPF. It always tries to get the vmlinux BTF from sysfs (`/sys/kernel/btf/vmlinux`) and falls back to search on-disk debug information (please see libbpf source for more details). Module BTFs would be taken from sysfs, but unlike vmlinux BTF, ipftrace2 doesn't find it from the disk because scanning the module debug info is complicated.

Reference: https://github.com/YutaroHayakawa/ipftrace2/blob/master/src/symsdb.c

### BPF programs

Currently, `ipftrace2` loads only five kprobe BPF programs to the kernel, named `ipft_mainN` (`ipft_main1` ~ `ipft_main5`). Then, it attaches the BPF program `ipft_mainN` to the kernel function, taking skb as an Nth argument. For example, it attaches `ipft_main2` to `void tcp_rcv_established(struct sock *sk, struct sk_buff *skb)` because skb is the second argument. What these BPF programs do is very simple. They read the `skb->mark` and match it with the value given by the user. If it doesn't match, do nothing. If it matches, collect the data and generate perf event sample.

If the user provides the extension BPF program, it is statically linked with all BPF programs before loading using libbpf's static linker feature. If it is not provided, the default "null" program (which does nothing useful) will be used.

Main BPF programs: https://github.com/YutaroHayakawa/ipftrace2/blob/master/src/ipft.bpf.c

Null extension program: https://github.com/YutaroHayakawa/ipftrace2/blob/master/src/null_module.bpf.c

### Decoding perf samples generated from the BPF programs

`ipftrace2` user space program makes some decording for the perf event samples generated by BPF programs. Currently only decording it does is resolving function address to function name with `kallsyms`.

Reference: https://github.com/YutaroHayakawa/ipftrace2/blob/master/src/symsdb.c

### Generating tracing output

 See [here](output.md) for more details.