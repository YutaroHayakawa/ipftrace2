# ipftrace2 Lua Scripting Manual

## Basic usage

`ipftrace2` provides the [Lua 5.3](https://www.lua.org/manual/5.3/) scripting interface to customize the output with extra data. You can provide following functions.

`init()` : Called before tracing . You can do any initialization you want in here. Don't have have to return anything.

`emit()` : Called before loading eBPF programs to the kernel. Must return eBPF byte code to collect custom data with binary string. Please see [Programming Environment for emit()](https://github.com/YutaroHayakawa/ipftrace2/blob/master/docs/scripting.md#programming-environment-for-emit) for more details

`dump(data)` : Called after tracing for each traces (can be called multiple times). Must return custom output string. `data` is a data which the eBPF program provided by `emit` collects. It is represented as a Lua binary string.

`fini()` : Called after everything. You can do any deinitialization you want in here. Don't  have to return anything.

## Programming Environment for emit()

### Terminologies

- Callee program: An eBPF program generated with `emit`.
- Caller program: An eBPF program of `ipftrace2` itself.

### ABI

The callee program will be concatenated to the caller program (we don't use tail call or BPF to BPF call, just concatenate it for better performance and support for older Linux kernel). From caller program point of view, the generated program is an **inlined function**. It will be called with following initial state.

```
Register state

The convention for caller-callee registers are the same as eBPF specification.
That means, R1 - R5 will be used as argument passing registers. You can modify
it for free. But you are responsible to save the R6 - R9 since it is a callee-
saved registers.

R0      -> Undefined.
R1      -> Pointer to the **64bytes** buffer which will be passed to the dump() later.
R2      -> Pointer to the eBPF context (it is not always a pointer to struct pt_regs, ipftrace2 may use different program types instead of kprobes).
R3      -> Pointer to skb.
R4      -> Reserved for future use. Currently, it is undefined.
R5      -> Reserved for future use. Currently, it is undefined.
R6 - R9 -> Undefined (Callee saved).
R10     -> Read only frame pointer.

Stack layout

eBPF has 512bytes of stack spaces. However, ipftrace2 only allows you to use the
subset of it. Following figure shows the stack layout. The areas named `user*`
are the places you can use. `user trace data` will be copied to the perf buffer
and passed to the dump() later. Please fill this area to collect custom data.

       +--------------------+
       | reserved           | 0   - 63
       |                    | 64  - 127
       +--------------------+
       | builtin trace data | 128 - 191
R1  -> +--------------------+
       | user trace data    | 192 - 255
       +--------------------+
       | user stack         | 256 - 319 
       |                    | 320 - 383 
       |                    | 384 - 447 
       |                    | 448 - 511
R10 -> +--------------------+
```

### Accessing to C debug information

To make your custom program work with different kernel versions, you may want to know the kernel version specific data like offset of the struct members or size of the typedef-ed types. To get such information, you can use following Lua helper functions to access to the kernel C debug information.

#### `ipft.offsetof(type_name, member_name)` 

Gets the offset of the C `struct` or `union` member. You don't have to put `struct` or `union` keyword to `type_name`  parameter. For example, you can get the offset of the `skb->head` with  `ipft.offsetof("sk_buff", "head")`.

#### `ipft.sizeof(type_name)`

Gets the size of the C types. For example, you can get the size of the `sk_buff_data_t` by  `ipft.sizeof("sk_buff_data_t")`.

#### `ipft.typeof(type_name, member_name)`

Gets the type of the struct/union members. For example, you can get the `skb->mark` by `ipft.typeof("sk_buff", "mark")`.

### Useful macro assemblers

You can use eBPF macro assemblers which is sililar to the one in the `linux/filter.h` without including any Lua libraries. Please see the examples under the `script` directory and `src/bpf.lua` for more details. Below is the example of how it is look like.

```lua
  --
  -- Emit the BPF code to read struct->member to memory
  --
  -- Parameters
  -- struct  : Name of the struct (string)
  -- member  : Name of the member (string)
  -- reg     : Register that holds the pointer to the struct (BPF.R0 - BPF.R9)
  -- push_fn : Function to allocate memory (function)
  --
  -- Returns: eBPF binary string to read struct->member to memory (string)
  --
  function emit_member_read(struct, member, dst_reg, src_reg, push_fn)
    member_offset = ipft.offsetof(struct, member)
    member_size = ipft.sizeof(ipft.typeof(struct, member))
    return BPF.emit({
      BPF.MOV64_REG(BPF.R1, dst_reg),
      BPF.ALU64_IMM(BPF.ADD, BPF.R1, push_fn(member_size)),
      BPF.MOV64_IMM(BPF.R2, member_size),
      BPF.MOV64_REG(BPF.R3, src_reg),
      BPF.ALU64_IMM(BPF.ADD, BPF.R3, member_offset),
      BPF.CALL_INSN(BPF.FUNC.probe_read),
    })
  end
```

## Did you feel like this is too difficult?

We are sure that programming environment for `emit` is too much difficult for eBPF bigginers. This is because the original author was not a good designer of the DSL and he was afraid of losing the flexibility due to his abstraction. That's why `ipftrace2` provides this kind of primitive API.

We won't support fancy DSL officially, but it is free to develop the useful DSL, idioms or code generators. If you came up with such useful stuff, let's contribute it to the issue with the link to the snnipet. We will consider to put it on the Wiki page :)
