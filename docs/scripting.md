# ipftrace2 Lua Scripting Manual

## Basic usage

`ipftrace2 ` provides the [Lua 5.3](https://www.lua.org/manual/5.3/) scripting interface to customize the output with extra data. You can provide following functions.

`init()` : Called before tracing . You can do any initialization you want in here. Don't have have to return anything.

`emit()` : Called before loading eBPF programs to the kernel (can be called multiple times). Must return eBPF byte code to collect custom data with binary string. Please see [Programming Environment for emit()](#Programming Environment for emit()) for more details

`dump(data)` : Called after tracing for each traces (can be called multiple times). Must return custom output string. `data` is a data which the eBPF program provided by `emit` collects. It is represented as a Lua binary string.

`fini()` : Called after everything. You can do any deinitialization you want in here. Don't  have to return anything.

## Programming Environment for emit()

### Terminologies

- Custom module: The eBPF program generated with `emit`.
- Caller program: The eBPF which calls custom module.

### ABI

The eBPF program generated from `emit` will be concatenated to the caller program (we don't use tail call or BPF to BPF call, just concatenate it for better performance and support for older Linux kernel). From main program point of view, the generated program is an **inlined function**. It will be called with following form.

```c
/*
 * Arg1 (R1) -> Pointer to the **64bytes** buffer which will be passed to dupm() later
 * Arg2 (R2) -> Pointer to the eBPF context (not always struct pt_regs *, ipftrace2 may use
 * different program types instead of kprobes).
 * Arg3 (R3) -> Pointer to skb
 */
void custom_function(uint8_t *buf, void *ctx, struct sk_buff *skb);
```

Like a normal function calls, you are responsible to save the callee-saved registers (R5 ~ R9). Please see [official document](https://www.kernel.org/doc/Documentation/networking/filter.txt) or [unofficial reference guide by Cilium](https://docs.cilium.io/en/latest/bpf/) for more details.

### Stack constraint

Custom module cannot use the entire stack area. It is limited to the area **from R10 - 0 to R10 - 256** area. Rest of the area will be used by caller program. Please be careful not to use that area.

### Accessing to C debug information

To make your custom program work with different kernel versions, you may want to know the version specific data like offset of the struct memebers or size of the typedef-ed types. To get such information, you can use following Lua helper functions to access to the kernel C debug information.

##### `ipft.offsetof(type_name, member_name)` 

Gets the offset of the C `struct` or `union` member. You don't have to put `struct` or `union` keyword to `type_name`  parameter. For example, you can get the offset of the `skb->head` with  `ipft.offsetof("sk_buff", "head")`.

##### `ipft.sizeof(type_name)`

Returns the size of the C types. For example, you can get the size of the `sk_buff_data_t` by  `ipft.sizeof("sk_buff_data_t")`.

### Useful macro assemblers

You can use eBPF macro assemblers which is sililar to the one in the `linux/filter.h` without including any Lua libraries. You can generate eBPF byte code binary string with `BPF.emit()`. Please see the examples under the `script` directory and `src/bpf.lua` for more details.

## Contributing for better programming experience

We are sure that programming environment for `emit` is too much difficult for eBPF bigginers. This is because the original author was not a good designer of the DSL and he was afraid of losing the flexibility due to his abstraction. That's why `ipftrace2` provides this kind of primitive API.

We won't support fancy DSL officially, but it is free to develop the useful DSL, idioms or code generators. If you came up with such useful stuff, let's contribute it to the issue with the link to the snnipet. We will consider to put it on the Wiki page :)
