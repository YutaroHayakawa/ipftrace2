# ipftrace2 Experimental BPF Extension Guide

ipftrace2 provides an extension mechanism to collect extra data and display it.
Such functionality is used to be provided through [Lua scripting](docs/lua_extension.md),
but we introduced a new mechanism described in this document to overcome some painpoints
such as

- Context switching of going BPF and Lua back and forth
- Burden of compiling BPF program everytime and embed it to Lua script
- Burden of dealing with decoding binary data in Lua

In this BPF-based extension mechanism, users don't need to write Lua script. The
extension is purely consists of BPF and users don't need to write code to decode
the event data.

## Basic Format

The format of the BPF program is almost the same as the one in Lua script. The only
difference is `__ipft_event_struct` annotation. You must define a special struct
annotated with `__ipft_event_struct` and must format the output data 
(`data[64]` buffer in the function argument). This tells ipftrace2 userspace
about the "format" of your output. Below is a minimal extension program.

```c
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define __ipft_sec_skip __attribute__((section("__ipft_skip")))
#define __ipft_ref(name) name __ipft_sec_skip
#define __ipft_event_struct __ipft_event_struct __ipft_sec_skip
#define __ipft_fmt_hex __attribute__((btf_decl_tag("ipft:fmt:hex")))
#define __ipft_fmt_enum(ref) __attribute__((btf_decl_tag("ipft:fmt:enum:" #ref)))
#define __ipft_fmt_enum_flags(ref) __attribute__((btf_decl_tag("ipft:fmt:enum_flags:" #ref)))

struct event {
  /* Your fields comes here */
  unsigned int len;
} __ipft_event_struct;

/*
 * This is an only subset of actual sk_buff definitions but no problem.
 * Because BPF-CORE feature of libbpf loader takes care of rewrite this
 * program based on actual definition from kernel BTF.
 */
struct sk_buff {
  /* Your fields comes here. Below is an example. */
  unsigned int len;
};

__hidden int
module(void *ctx, struct sk_buff *skb, __u8 data[64])
{
  struct event *ev = (struct event *)data;

  /* Your logic comes here. Below is an example. */
  ev->len = BPF_CORE_READ(skb, len);

  return 0;
}
```

That's it. The output would looks like this. You can find your `len` information is appended to
the end of the trace.

```
464048546191357      005             nf_conntrack                ipv4_conntrack_in ( len: 2688 )
464048546194045      005             nf_conntrack                  nf_conntrack_in ( len: 2688 )
464048546194858      005             nf_conntrack                resolve_normal_ct ( len: 2688 )
464048546195703      005             nf_conntrack       nf_conntrack_handle_packet ( len: 2688 )
464048546196407      005             nf_conntrack          nf_conntrack_tcp_packet ( len: 2688 )
464048546197050      005                  vmlinux                      nf_checksum ( len: 2688 )
464048546197694      005                  vmlinux                   nf_ip_checksum ( len: 2688 )
464048546198546      005                   nf_nat          nf_nat_ipv4_pre_routing ( len: 2688 )
464048546199226      005                   nf_nat                   nf_nat_inet_fn ( len: 2688 )
464048546207009      005                  vmlinux               tcp_v4_early_demux ( len: 2688 )
464048546208553      005                  vmlinux                 ip_local_deliver ( len: 2688 )
464048546209310      005                  vmlinux                     nf_hook_slow ( len: 2688 )
```

## Usage

You can use BPF-based extension in two ways. The first way is passing the C source directly to `ipft`.

```
$ sudo ipft -e extension.bpf.c -m 0xdeadbeef
```

The C source must have `.c` suffix. When `ipft` finds such an input, it tries to compile the program
using `clang` on your local system and directly use the generated BPF ELF object. This requires `clang`
to be installed, but gives you a faster feedback cycle, so useful while you are developing the module.

It internally uses `popen`, so uses your shell to invoke `clang`. If you want to change the C compiler
command from the default, you can define `CC` environment variable. Also, if you wish to pass an extra
C compiler flags, you can define `CFLAGS` environment variable.

The second way to use it is passing compiled ELF object file to `ipft`.

```
// BPF-based extension uses BTF internally, so must put `-g` option.
$ clang -target bpf -O2 -g -c example.c
$ sudo ipft -e extension.bpf.o -m 0xdeadbeef
```

The object file must have `.o` suffix. When `ipft` finds such an input, it directly uses the object
file. When you distribute your ipftrace2 module to others, object file would be a good option. It
doesn't need `clang` to be installed on your system, but still works everywhere thanks to the [BPF
CO-RE](https://nakryiko.com/posts/bpf-core-reference-guide/).

## Development Tips

You can start your development by generating the extension skeleton with
`ipft --gen bpf-module-skeleton` command. It generates a minimal skeleton of the BPF extension (actually,
the above example is generated by this command). Usually, you need to rely on [libbpf](https://github.com/libbpf/libbpf)
header files to write BPF program such as `bpf_core_read.h`.

If you don't need the full skeleton and only need the macro definition such as `__ipft_event_struct` in
the form of the header file, you can run `ipft --gen bpf-module-header` command. It gives you an output
like this.

```c
#ifndef __IPFT_EXTENSION_H__
#define __IPFT_EXTENSION_H__

#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define __ipft_sec_skip __attribute__((section("__ipft_skip")))
#define __ipft_ref(name) name __ipft_sec_skip
#define __ipft_event_struct __ipft_event_struct __ipft_sec_skip
#define __ipft_fmt_hex __attribute__((btf_decl_tag("ipft:fmt:hex")))
#define __ipft_fmt_enum(ref) __attribute__((btf_decl_tag("ipft:fmt:enum:" #ref)))
#define __ipft_fmt_enum_flags(ref) __attribute__((btf_decl_tag("ipft:fmt:enum_flags:" #ref)))

#endif
```
