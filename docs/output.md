# ipftrace2 Output Specification

`ipftrace2` provides two types of output; **aggregated** output and **streaming** output. **Aggregated** output keeps tracing samples on memory and displays aggregated results to standard output at the end of tracing. Since it keeps all tracing data on memory, it is not suitable for long-running analysis. On the other hand, **streaming** output streams the tracing samples to standard output in real time without keeping tracing data to memory. It is memory efficient, but users are responsible for making an aggregation.

## Currently supported output formats

### Aggregate

Can be used with `-o aggregate`. This is a human-readable aggregated output which is suitable for quick analysis. It keeps all tracing samples on memory. Therefore, shouldn't be used for long-running tracing or tracing with high packet rate.

It aggregates the function call trace of individual packets, sorts them by timestamp, and outputs the trace of each packet separated by `===`.

#### How to read

Below is an example output including script output. Each lines are corresponds to the single tracing sample. From the left, it shows time stamp, processor id, function name, and script output (in the brackets). Lines surrounded by `===` are the traces of single packet [basically](#what-is-packet_id).

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
96976848855606       000                raw_local_deliver ( len: 2802 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848859538       000                       tcp_v4_rcv ( len: 2802 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848864010       000                       tcp_filter ( len: 2802 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848868431       000               sk_filter_trim_cap ( len: 2802 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848872929       000      __cgroup_bpf_run_filter_skb ( len: 2802 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848877233       000            security_sock_rcv_skb ( len: 2802 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848898045       000      selinux_socket_sock_rcv_skb ( len: 2802 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848923670       000                   tcp_v4_fill_cb ( len: 2802 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848930349       000                    tcp_v4_do_rcv ( len: 2802 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848934891       000              tcp_rcv_established ( len: 2802 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976848976623       000                          tcp_urg ( len: 2802 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976849016895       000                   tcp_data_queue ( len: 2802 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976849025342       000            tcp_try_rmem_schedule ( len: 2782 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976849030982       000                    tcp_queue_rcv ( len: 2782 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976849049627       000              tcp_event_data_recv ( len: 2782 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976849055966       000                kfree_skb_partial ( len: 2782 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976849061666       000           skb_release_head_state ( len: 2782 gso_segs: 2 gso_type: tcpv4 gso_size: 1460 )
96976853016795       000                      nf_checksum ( len: 16837 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853036534       000                   nf_ip_checksum ( len: 16837 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853046235       000                ip_route_use_hint ( len: 16837 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853053051       000              fib_validate_source ( len: 16837 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853098636       000            __fib_validate_source ( len: 16837 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853150680       000                 ip_local_deliver ( len: 16837 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853156737       000                     nf_hook_slow ( len: 16837 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853162061       000          ip_local_deliver_finish ( len: 16837 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853167734       000          ip_protocol_deliver_rcu ( len: 16817 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853172893       000                raw_local_deliver ( len: 16817 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853177945       000                       tcp_v4_rcv ( len: 16817 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853183789       000                       tcp_filter ( len: 16817 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853189311       000               sk_filter_trim_cap ( len: 16817 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853194856       000      __cgroup_bpf_run_filter_skb ( len: 16817 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853200585       000            security_sock_rcv_skb ( len: 16817 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853207748       000      selinux_socket_sock_rcv_skb ( len: 16817 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853218531       000                   tcp_v4_fill_cb ( len: 16817 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853224339       000                    tcp_v4_do_rcv ( len: 16817 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853229616       000              tcp_rcv_established ( len: 16817 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853236513       000                          tcp_urg ( len: 16817 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853243244       000                   tcp_data_queue ( len: 16817 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853249286       000            tcp_try_rmem_schedule ( len: 16797 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853280427       000                    tcp_queue_rcv ( len: 16797 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853302881       000              tcp_event_data_recv ( len: 16797 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853310871       000                kfree_skb_partial ( len: 16797 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976853316518       000           skb_release_head_state ( len: 16797 gso_segs: 12 gso_type: tcpv4 gso_size: 1460 )
96976856958532       000                      nf_checksum ( len: 7294 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976856971369       000                   nf_ip_checksum ( len: 7294 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976856976069       000               tcp_v4_early_demux ( len: 7294 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976856980578       000                 ip_local_deliver ( len: 7294 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976856984480       000                     nf_hook_slow ( len: 7294 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976856988902       000          ip_local_deliver_finish ( len: 7294 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976856993245       000          ip_protocol_deliver_rcu ( len: 7274 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976856997567       000                raw_local_deliver ( len: 7274 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857001500       000                       tcp_v4_rcv ( len: 7274 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857005592       000                       tcp_filter ( len: 7274 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857009637       000               sk_filter_trim_cap ( len: 7274 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857013694       000      __cgroup_bpf_run_filter_skb ( len: 7274 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857017833       000            security_sock_rcv_skb ( len: 7274 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857021921       000      selinux_socket_sock_rcv_skb ( len: 7274 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857025924       000                   tcp_v4_fill_cb ( len: 7274 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857030027       000                    tcp_v4_do_rcv ( len: 7274 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857033953       000              tcp_rcv_established ( len: 7274 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857038325       000                          tcp_urg ( len: 7274 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857042562       000                   tcp_data_queue ( len: 7274 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857047054       000            tcp_try_rmem_schedule ( len: 7254 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857052553       000                    tcp_queue_rcv ( len: 7254 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857067464       000              tcp_event_data_recv ( len: 7254 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857073353       000                kfree_skb_partial ( len: 7254 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
96976857077328       000           skb_release_head_state ( len: 7254 gso_segs: 5 gso_type: tcpv4 gso_size: 1460 )
===
96976847841853       000                      nf_checksum ( len: 1452 gso_segs: 0 gso_type: none gso_size: 0 )
96976847847215       000                   nf_ip_checksum ( len: 1452 gso_segs: 0 gso_type: none gso_size: 0 )
96976847878634       000                ip_route_use_hint ( len: 1452 gso_segs: 0 gso_type: none gso_size: 0 )
<skip...>
```

### JSON

Can be used with `-o json`. This is a machine-readable streaming output that streams each tracing samples with JSON format.

#### How to read

Below is an example output including script output. Each line is a single JSON string corresponds to the single tracing sample.

```json
Trace ready!
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975289656,"processor_id":0,"function":"nf_checksum","gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975313708,"processor_id":0,"function":"nf_ip_checksum","gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975320622,"processor_id":0,"function":"__skb_checksum_complete","gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975329718,"processor_id":0,"function":"ip_rcv_finish","gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975337610,"processor_id":0,"function":"tcp_v4_early_demux","gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975348829,"processor_id":0,"function":"ip_route_input_noref","gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975356034,"processor_id":0,"function":"ip_route_input_rcu","gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975362481,"processor_id":0,"function":"ip_route_input_slow","gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975373576,"processor_id":0,"function":"fib_validate_source","gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975380427,"processor_id":0,"function":"__fib_validate_source","gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975388346,"processor_id":0,"function":"ip_local_deliver","gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975394161,"processor_id":0,"function":"nf_hook_slow","gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975404255,"processor_id":0,"function":"ip_local_deliver_finish","gso_size":"0","gso_segs":"0","len":"44","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975411527,"processor_id":0,"function":"ip_protocol_deliver_rcu","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975419296,"processor_id":0,"function":"raw_local_deliver","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975425355,"processor_id":0,"function":"tcp_v4_rcv","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975433401,"processor_id":0,"function":"tcp_filter","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975440566,"processor_id":0,"function":"sk_filter_trim_cap","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975449698,"processor_id":0,"function":"__cgroup_bpf_run_filter_skb","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975457467,"processor_id":0,"function":"security_sock_rcv_skb","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975465651,"processor_id":0,"function":"selinux_socket_sock_rcv_skb","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975472504,"processor_id":0,"function":"tcp_v4_fill_cb","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975479418,"processor_id":0,"function":"tcp_v4_do_rcv","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975486281,"processor_id":0,"function":"tcp_rcv_state_process","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975506487,"processor_id":0,"function":"tcp_finish_connect","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975513233,"processor_id":0,"function":"security_inet_conn_established","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975522169,"processor_id":0,"function":"selinux_inet_conn_established","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975529440,"processor_id":0,"function":"selinux_skb_peerlbl_sid","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975535585,"processor_id":0,"function":"selinux_xfrm_skb_sid","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975544879,"processor_id":0,"function":"selinux_xfrm_skb_sid_ingress","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975552247,"processor_id":0,"function":"selinux_netlbl_skbuff_getsid","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975560155,"processor_id":0,"function":"tcp_init_transfer","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975628660,"processor_id":0,"function":"tcp_urg","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975635250,"processor_id":0,"function":"__kfree_skb","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975641195,"processor_id":0,"function":"skb_release_head_state","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975647083,"processor_id":0,"function":"skb_release_data","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4e00","timestamp":22575975653048,"processor_id":0,"function":"kfree_skbmem","gso_size":"0","gso_segs":"0","len":"24","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4900","timestamp":22575984647806,"processor_id":0,"function":"nf_checksum","gso_size":"0","gso_segs":"0","len":"40","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4900","timestamp":22575984676904,"processor_id":0,"function":"nf_ip_checksum","gso_size":"0","gso_segs":"0","len":"40","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4900","timestamp":22575984682030,"processor_id":0,"function":"__skb_checksum_complete","gso_size":"0","gso_segs":"0","len":"40","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4900","timestamp":22575984687971,"processor_id":0,"function":"ip_rcv_finish","gso_size":"0","gso_segs":"0","len":"40","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4900","timestamp":22575984693807,"processor_id":0,"function":"tcp_v4_early_demux","gso_size":"0","gso_segs":"0","len":"40","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4900","timestamp":22575984700426,"processor_id":0,"function":"ip_local_deliver","gso_size":"0","gso_segs":"0","len":"40","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4900","timestamp":22575984704676,"processor_id":0,"function":"nf_hook_slow","gso_size":"0","gso_segs":"0","len":"40","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4900","timestamp":22575984709997,"processor_id":0,"function":"ip_local_deliver_finish","gso_size":"0","gso_segs":"0","len":"40","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4900","timestamp":22575984715317,"processor_id":0,"function":"ip_protocol_deliver_rcu","gso_size":"0","gso_segs":"0","len":"20","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4900","timestamp":22575984721012,"processor_id":0,"function":"raw_local_deliver","gso_size":"0","gso_segs":"0","len":"20","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4900","timestamp":22575984725589,"processor_id":0,"function":"tcp_v4_rcv","gso_size":"0","gso_segs":"0","len":"20","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4900","timestamp":22575984752787,"processor_id":0,"function":"tcp_filter","gso_size":"0","gso_segs":"0","len":"20","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4900","timestamp":22575984758746,"processor_id":0,"function":"sk_filter_trim_cap","gso_size":"0","gso_segs":"0","len":"20","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4900","timestamp":22575984764166,"processor_id":0,"function":"__cgroup_bpf_run_filter_skb","gso_size":"0","gso_segs":"0","len":"20","gso_type":"none"}
{"packet_id":"0xffff9ec7c4ef4900","timestamp":22575984769771,"processor_id":0,"function":"security_sock_rcv_skb","gso_size":"0","gso_segs":"0","len":"20","gso_type":"none"}
<skip...>
```

Meaning of each JSON elements are below.

| Key                               | Value                                                        |
| --------------------------------- | ------------------------------------------------------------ |
| packet_id                         | String that can identify individual packets                  |
| timestamp                         | Time that the trace was sampled (see `bpf_ktime_get_ns` in `man bpf-healpers (7)`) |
| processor_id                      | Processor that the trace was sampled (see `bpf_get_smp_processor_id` in `man bpf-healpers (7)`) |
| function                          | The name of the function                                     |
| gso_size, gso_segs, len, gso_type | Data provided by script. The meaning of key/value depends on users |

#### How to aggregate

In [examples/aggregation/aggregate.py](https://github.com/YutaroHayakawa/ipftrace2/blob/master/example/aggregation/aggregate.py) we have a minimal example of how to aggregate samples with Python.

## What is packet\_id?

`packet_id` is an ID that can identify individual `struct sk_buff` inside the kernel. 

`ipftrace2` is a tool to trace which function a packet passed through in the kernel. The packet here is technically a `struct sk_buff`. `iptrace2` internally attaches a BPF program to a function that takes `struct sk_buff` as an argument, and records the function calls. At this point, when we have two `struct sk_buff`, skb1 and skb2, we need a unique ID to distinguish each of them in order to know how to distinguish a series of function calls between them. This is where the `packet_id` comes in.

The Linux kernel does not explicitly provide such an ID. Therefore, `ipftrace2` currently uses the **pointer to `struct sk_buff`** as the `packet_id`. However, this method is not perfect. The memory area can be reused, so the same pointer may appear again. Furthermore, Linux currently allocates `struct sk_buff` from the memory pool, so it is highly likely to be reused.

It is possible that a kernel update in the future could provide a truly unique ID in some way. This is why we currently use vague names like `packet_id` instead of names like `skb_pointer`.
