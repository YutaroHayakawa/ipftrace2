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

## Program Structure

The structure of the BPF program is almost the same as the one in Lua script. The only
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

### Format Specifiers

By default, `ipft` formats your field based on the type of the fields. Here, we have a list
of "default" format of each C primitive types.

- Signed integer types (int, short, long, etc) => signed integer (e.g. `10`, `-1`)
- Unsigned integer types (unsigned int, unsigned short, etc) => unsigned integer (e.g. `10`, `20`)
- char => ASCII character (e.g. `a`, `b`, `C`)
- bool => `true` or `false`
- Pointer => Hex representation of the pointer (e.g. `0x00000000111111`)

You can override this default format by annotating your struct fields with "Format Specifier".
For example, `__ipft_fmt_hex` formats annotated field with hex. You can use it like following.

```c
struct event {
  unsigned int len __ipft_fmt_hex;
} __ipft_event_struct;
```

Then it should produces output like this.

```
464048546191357      005             nf_conntrack                ipv4_conntrack_in ( len: 0xa80 )
```

Following is a list of supported format specifiers.

#### __ipft_fmt_hex

Formats the field as a hex decimal.

```c
struct event {
  unsigned int len __ipft_fmt_hex;
} __ipft_event_struct;
```

Output

```
464048546191357      005             nf_conntrack                ipv4_conntrack_in ( len: 0xa80 )
```

#### __ipft_fmt_enum(ref)

Formats the field with the name of the `enum` field. You need to declare the `enum` used for formatting
beforehand with `__ipft_ref` annotation and reference it from `__ipft_fmt_enum`.

```c
enum {
  tcpv4           = 1 << 0,
  dodgy           = 1 << 1,
  tcp_ecn         = 1 << 2,
  tcp_fixedid     = 1 << 3,
  tcpv6           = 1 << 4,
  fcoe            = 1 << 5,
  gre             = 1 << 6,
  gre_csum        = 1 << 7,
  ipxip4          = 1 << 8,
  ipxip6          = 1 << 9,
  udp_tunnel      = 1 << 10,
  udp_tunnel_csum = 1 << 11,
  partial         = 1 << 12,
  tunnel_remcsum  = 1 << 13,
  sctp            = 1 << 14,
  esp             = 1 << 15,
  udp             = 1 << 16,
  udp_l4          = 1 << 17,
  flaglist        = 1 << 18,
} __ipft_ref(gso_types);

struct event {
  unsigned int len;
  __u16 gso_size;
  __u16 gso_segs;
  __u32 gso_type __ipft_fmt_enum(gso_types);
} __ipft_event_struct;
```

Output with `__ipft_fmt_hex`

```
3146600050450265     005                  vmlinux             ip_route_input_noref ( gso_type: 0x1 )
```

Output with `__ipft_fmt_enum`

```
3146600050450265     005                  vmlinux             ip_route_input_noref ( gso_type: tcpv4 )
```

#### __ipft_fmt_enum_flag(ref)

Similar to `__ipft_fmt_enum`, but interprets the field as a bit flag and prints all active bits.

Output with `__ipft_fmt_hex`

```
3146600050597677     004                  vmlinux             ip_route_input_noref ( gso_type: 0x101 )
```

Output with `__ipft_fmt_enum_flag`

```
3146505009019580     000                  vmlinux             ip_route_input_noref ( gso_type: tcpv4|ipxip4 )
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
