# ipftrace2 Lua Scripting Manual (API version 1)

`ipftrace2` provides the C and [Lua 5.4](https://www.lua.org/manual/5.4/) scripting interface to customize the output with extra data. You can customize your output by providing the C program and Lua script like following.

## C Program

### Basic format

```c
#include <stdint.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/*
 * You can use libbpf-style C programming. The program you provid will
 * be linked together with ipftrace2 main program with "static linking"
 * feature of libbpf.
 *
 * We strongly encourage you to use BPF CO-RE helpers such as
 * `BPF_CORE_READ` provided by libbpf. Then your program automatically
 * become independent from kernel versions.
 *
 * See below for more details about CO-RE
 * https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html
 * https://facebookmicrosites.github.io/bpf/blog/2020/02/20/bcc-to-libbpf-howto-guide.html
 */

/*
 * CO-RE style kernel struct definition. You can only declare the subset
 * of struct sk_buff you are interested in here.
 */
struct sk_buff {
  uint32_t mark;
};

struct example_info {
  uint32_t mark;
};

/*
 * You must provide this "module" function. Collect any information you
 * want and write them to `data` buffer. Currently it is limited to the
 * 64 Bytes for better performance. The information you write to `data`
 * will be passed to the Lua script when ipftrace2 output the trace.
 *
 * Please return 0 if your module finish successfully. Otherwise please
 * return -1, then ipftrace2 main program returns without generating
 * any trace event.
 *
 * Annotating the function with __hidden is essential. Otherwise your
 * program will not pass the verification with kernel older than 5.12.
 *
 * See below for more details about the background for __hidden
 * https://github.com/libbpf/libbpf/commit/3319982d34ddc51a2807ccc92445d9a9d9089dcf
 * https://github.com/torvalds/linux/commit/e5069b9c23b3857db986c58801bebe450cff3392
 */
__hidden int
module(struct pt_regs *ctx, struct sk_buff *skb, uint8_t data[64])
{
  struct example_info *info = (struct example_info *)data;

  info->mark = BPF_CORE_READ(skb, mark);

  return 0;
}
```

### Compile

```
// Need Clang 10 or later built with LLVM BPF backend
$ clang -target bpf -O3 -c -g foo.bpf.c -o foo.bpf.o
```

## Lua script

```lua
-- Must be provided for future extensions. Currently, only valid choice is 1.
api_version = 1

function init()
  -- Called only once before anything. You can do any initialization in here.
  print("init")
end

function emit()
  -- Emit compiled ELF image of C custom program with binary string. You can
  -- also embed binary string directly to here. A quick one liner to generate
  -- string binary string is following.
  --
  -- od -An -tx1 -v foo.bpf.o | sed "s/ /\\\x/g" | tr -d "\n"
  --
  return io.open("foo.bpf.o", "rb"):read("*all")
end

function dump(data)
  -- Called multiple times for every tracing output. Parse binary data (which
  -- comes from `data` buffer of C module() function) and generate flat table
  -- that maps string to string/number. Type other than string/number or nested
  -- tables are not supported currently.
  mark = string.unpack("=I4", data)
  return {
    mark=mark
  }
end

function fini()
  -- Called only once after everything. You can do any finalization in here.
  print("fini")
end
```

## Use it

```
$ sudo ipft -m 0xdeadbeef -s foo.lua
```
