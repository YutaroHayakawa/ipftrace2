# ipftrace2 Lua Scripting Manual (API version 1)

`ipftrace2` provides the C and [Lua 5.4](https://www.lua.org/manual/5.4/) scripting interface to customize the output with extra data. You can customize your output by providing the C program and Lua script like following.

## C Program

### Basic format

```c
/*
 * Install libbpf to use these headers
 */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

/*
 * You can use libbpf-style C programming, but currently, there are some
 * limitations.
 *
 * 1. You cannot use global entities like global varialbles or maps.
 * 2. You cannot define multiple functions. Only single function named
 *    "module" is allowed.
 * 3. You cannot use function calls.
 */

struct sk_buff {
  uint32_t mark;
};

struct example_info {
  uint32_t mark;
};

/* Function name must be "module" */
int module(void *ctx, struct sk_buff *skb, uint8_t data[64])
{
  struct example_info *info = (struct example_info *)data;

  info->mark = BPF_CORE_READ(skb, mark);

  return 0;
}
```

### Compile

```
$ clang -target bpf -O3 -c -g foo.bpf.c
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
  -- also embed binary string directly to here.
  return io.open("foo.bpf.o", "rb"):read("*all")
end

function dump(data)
  -- Called multiple times for every tracing output. Parse binary data (which
  -- comes from third argument of C module() function) and generate human-readable
  -- string. It will be appended to the end of default tracing output.
  mark = string.unpack("=I4", data)
  return string.format("(mark: 0x%x)", mark)
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
