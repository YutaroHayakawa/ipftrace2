# ipftrace2 Output Specification

`ipftrace2` provides two types of output; **aggregated** output and **streaming** output. **Aggregated** output keeps tracing samples on memory and displays aggregated results to standard output at the end of tracing. Since it keeps all tracing data on memory, it is not suitable for long-running analysis. On the other hand, **streaming** output streams the tracing samples to standard output in real time without keeping tracing data to memory. It is memory efficient, but users are responsible for making an aggregation.

## Currently supported output formats

### Aggregate

Can be used with `-o aggregate`. This is a human-readable aggregated output which is suitable for quick analysis. It keeps all tracing samples on memory. Therefore, shouldn't be used for long-running tracing or tracing with high packet rate.

It aggregates the function call trace of individual packets, sorts them by timestamp, and outputs the trace of each packet separated by `===`.

#### How to read (function tracer)

Below is an example output of function tracer (`-t functon` or default) including script output. Each lines are corresponds to the single tracing sample. From the left, it shows time stamp, processor id, function name, and script output (in the brackets). Lines surrounded by `===` are the traces of single packet [basically](#what-is-packet_id).

```
<skip...>
Attaching program (total 1303, succeeded 1303, failed 0, filtered: 0)
Trace ready!
Got 657 traces^C
Timestamp            CPU                         Function
===
96976848684329       000                      nf_checksum ( len: 2822 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848692769       000                   nf_ip_checksum ( len: 2822 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848765647       000               tcp_v4_early_demux ( len: 2822 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848836855       000                 ip_local_deliver ( len: 2822 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848840849       000                     nf_hook_slow ( len: 2822 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848846012       000          ip_local_deliver_finish ( len: 2822 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848851032       000          ip_protocol_deliver_rcu ( len: 2802 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
<skip...>
===
96976847841853       000                      nf_checksum ( len: 1452 gso_segs: 0 gso_type: none gso_size: 0 )
96976847847215       000                   nf_ip_checksum ( len: 1452 gso_segs: 0 gso_type: none gso_size: 0 )
96976847878634       000                ip_route_use_hint ( len: 1452 gso_segs: 0 gso_type: none gso_size: 0 )
<skip...>
```

#### How to read (function graph tracer)

Below is an example output of function graph tracer (`-t functon_graph`) including script output. Most of the output is the same as function tracer. The function name shows the call of the function and `}` shows return.

```
25052836431430       000 ip_local_deliver() {                                             ( gso_size: 0 gso_type: none len: 40 gso_segs: 0 )
25052836432676       000   nf_hook_slow() {                                               ( gso_size: 0 gso_type: none len: 40 gso_segs: 0 )
25052836434607       000   }                                                              ( gso_size: 0 gso_type: none len: 40 gso_segs: 0 )
25052836436150       000   ip_local_deliver_finish() {                                    ( gso_size: 0 gso_type: none len: 40 gso_segs: 0 )
25052836437630       000     ip_protocol_deliver_rcu() {                                  ( gso_size: 0 gso_type: none len: 20 gso_segs: 0 )
25052836439206       000       raw_local_deliver() {                                      ( gso_size: 0 gso_type: none len: 20 gso_segs: 0 )
25052836440512       000       }                                                          ( gso_size: 0 gso_type: none len: 20 gso_segs: 0 )
25052836441960       000       tcp_v4_rcv() {                                             ( gso_size: 0 gso_type: none len: 20 gso_segs: 0 )
25052836443697       000         tcp_filter() {                                           ( gso_size: 0 gso_type: none len: 20 gso_segs: 0 )
25052836445190       000           sk_filter_trim_cap() {                                 ( gso_size: 0 gso_type: none len: 20 gso_segs: 0 )
25052836446698       000             __cgroup_bpf_run_filter_skb() {                      ( gso_size: 0 gso_type: none len: 20 gso_segs: 0 )
25052836448094       000             }                                                    ( gso_size: 0 gso_type: none len: 20 gso_segs: 0 )
25052836449602       000             security_sock_rcv_skb() {                            ( gso_size: 0 gso_type: none len: 20 gso_segs: 0 )
25052836451210       000               selinux_socket_sock_rcv_skb() {                    ( gso_size: 0 gso_type: none len: 20 gso_segs: 0 )
25052836452632       000               }                                                  ( gso_size: 0 gso_type: none len: 20 gso_segs: 0 )
25052836454196       000               bpf_lsm_socket_sock_rcv_skb() {                    ( gso_size: 0 gso_type: none len: 20 gso_segs: 0 )
<skip...>
===
25052813709178       000 selinux_ipv4_output() {                                          ( gso_size: 0 gso_type: tcpv4 len: 40 gso_segs: 1 )
25052813711218       000 }                                                                ( gso_size: 0 gso_type: tcpv4 len: 40 gso_segs: 1 )
25052813714478       000 }                                                                ( gso_size: 0 gso_type: tcpv4 len: 40 gso_segs: 1 )
25052813716025       000 }                                                                ( gso_size: 0 gso_type: tcpv4 len: 40 gso_segs: 1 )
25052813717735       000 ip_output() {                                                    ( gso_size: 0 gso_type: tcpv4 len: 40 gso_segs: 1 )
25052813719258       000   nf_hook_slow() {                                               ( gso_size: 0 gso_type: tcpv4 len: 40 gso_segs: 1 )
25052813720978       000     selinux_ipv4_postroute() {                                   ( gso_size: 0 gso_type: tcpv4 len: 40 gso_segs: 1 )
25052813722678       000       selinux_ip_postroute() {      
<skip...>
```

### JSON

Can be used with `-o json`. This is a machine-readable streaming output that streams each tracing samples with JSON format.

#### How to read (function tracer)

Below is an example output of function tracer (`-t functon` or default) including script output. Each line is a single JSON string corresponds to the single tracing sample.

```json
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975289656,"processor_id":0,"function":"nf_checksum","is_return":false,"gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975313708,"processor_id":0,"function":"nf_ip_checksum","is_return":false,"gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975320622,"processor_id":0,"function":"__skb_checksum_complete","is_return":false,"gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975329718,"processor_id":0,"function":"ip_rcv_finish","is_return":false,"gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975337610,"processor_id":0,"function":"tcp_v4_early_demux","is_return":false,"gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975348829,"processor_id":0,"function":"ip_route_input_noref","is_return":false,"gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975356034,"processor_id":0,"function":"ip_route_input_rcu","is_return":false,"gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
<skip...>
```

#### How to read (function graph tracer)

Below is an example output of function graph tracer (`-t functon_graph`) including script output. The only difference is `is_return` field can be set to `true` since function graph tracer traces function return as well.

```json
{"packet_id":"0xffff8dee8aea9700","timestamp":25340022557487,"processor_id":0,"function":"validate_xmit_xfrm","is_return":false,"gso_size":"0","len":"54","gso_type":"tcpv4","gso_segs":"1"}
{"packet_id":"0xffff8dee8aea9700","timestamp":25340022558860,"processor_id":0,"function":"validate_xmit_xfrm","is_return":true,"gso_size":"0","len":"54","gso_type":"tcpv4","gso_segs":"1"}
{"packet_id":"0xffff8dee8aea9700","timestamp":25340022560159,"processor_id":0,"function":"validate_xmit_skb","is_return":true,"gso_size":"0","len":"54","gso_type":"tcpv4","gso_segs":"1"}
{"packet_id":"0xffff8dee8aea9700","timestamp":25340022561440,"processor_id":0,"function":"validate_xmit_skb_list","is_return":true,"gso_size":"0","len":"54","gso_type":"tcpv4","gso_segs":"1"}
{"packet_id":"0xffff8dee8aea9700","timestamp":25340022572083,"processor_id":0,"function":"dev_hard_start_xmit","is_return":false,"gso_size":"0","len":"54","gso_type":"tcpv4","gso_segs":"1"}
{"packet_id":"0xffff8dee8aea9700","timestamp":25340022574087,"processor_id":0,"function":"skb_clone_tx_timestamp","is_return":false,"gso_size":"0","len":"54","gso_type":"tcpv4","gso_segs":"1"}
{"packet_id":"0xffff8dee8aea9700","timestamp":25340022575519,"processor_id":0,"function":"skb_clone_tx_timestamp","is_return":true,"gso_size":"0","len":"54","gso_type":"tcpv4","gso_segs":"1"}
```

Meaning of each JSON elements are below.

| Key                               | Value                                                        |
| --------------------------------- | ------------------------------------------------------------ |
| packet_id                         | String that can identify individual packets                  |
| timestamp                         | Time that the trace was sampled (see `bpf_ktime_get_ns` in `man bpf-healpers (7)`) |
| processor_id                      | Processor that the trace was sampled (see `bpf_get_smp_processor_id` in `man bpf-healpers (7)`) |
| function                          | The name of the function                                     |
| is_return                         | Whether the trace is a function return or not                |
| gso_size, gso_segs, len, gso_type | Data provided by script. The meaning of key/value depends on users |

#### How to aggregate

In [examples/aggregation/aggregate.py](https://github.com/YutaroHayakawa/ipftrace2/blob/master/example/aggregation/aggregate.py) we have a minimal example of how to aggregate samples with Python.

## What is packet\_id?

`packet_id` is an ID that can identify individual `struct sk_buff` inside the kernel. 

`ipftrace2` is a tool to trace which function a packet passed through in the kernel. The packet here is technically a `struct sk_buff`. `iptrace2` internally attaches a BPF program to a function that takes `struct sk_buff` as an argument, and records the function calls. At this point, when we have two `struct sk_buff`, skb1 and skb2, we need a unique ID to distinguish each of them in order to know how to distinguish a series of function calls between them. This is where the `packet_id` comes in.

The Linux kernel does not explicitly provide such an ID. Therefore, `ipftrace2` currently uses the **pointer to `struct sk_buff`** as the `packet_id`. However, this method is not perfect. The memory area can be reused, so the same pointer may appear again. Furthermore, Linux currently allocates `struct sk_buff` from the memory pool, so it is highly likely to be reused.

It is possible that a kernel update in the future could provide a truly unique ID in some way. This is why we currently use vague names like `packet_id` instead of names like `skb_pointer`.
