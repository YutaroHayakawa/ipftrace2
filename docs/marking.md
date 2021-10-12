# ipftrace2 Packet Marking Cheat Sheet

Marking the packet is what you'll need to do first when you use `ipftrace2` . This document is a chat sheet that collects the variety of ways to mark the packet.

## Places that we can mark the packet

Here we have a diagram that shows where and how we can mark the packet. There are a lot of the places we can mark the packet, but this diagram only shows the "meaningful" place for `ipftrace2` tracing. Since `ipftrace2` only generates the tracing sample when the packet is marked, to maximize the tracing coverage, you should mark the packet as early as possible. For example, in the TX path, the earliest possible place to mark the packet is `SO_MARK` . In the RX path,  XDP metadata is the earliest. However, both of them requires us to write some program. If you don't want to write a program, `tc` or `iptables (netfilter)` are easier to use.

![ipftrace2_marking.drawio.pdf](ipftrace2_marking.drawio.pdf)

## Useful things to know about the mark

### Mark can be overridden by another software

There are many existing softwares who are using the mark. Even if you mark the packet by yourself, it is possible to be overridden. But in other words, if you know how another software mark the packet, you can use their mark instead of marking the packets by yourselves. Here is a very useful list of the software using the mark and how they are using it.

https://github.com/fwmark/registry

### Mark is netns scoped

When the packets crosses the boundary of the Linux network namespace (e.g. cross the veth pair, cross the tunnel, etc...), the mark will be erased. This is useful when you are tracing inside the container. For example, if you mark the packet inside the container, you only see the function calles happened inside the container, you won't see the function calls happend in the host side network.

See: https://github.com/torvalds/linux/blob/626bf91a292e2035af5b9d9cce35c5c138dfe06d/net/core/skbuff.c#L5469

## Marking examples

Filter the packet with source IP address

```
sudo iptables -t raw -A PREROUTING -s 10.0.0.1 -j MARK --set-mark 0xdeadbeef
```

Of course, IPv6 works

```
sudo ip6tables -t raw -A PREROUTING -s 2001:0db8::1 -j MARK --set-mark 0xdeadbeef
```

Using `tc-ingress` + `u32` to match

```
sudo tc filter add dev eth0 parent ffff: protocol ip prio 1 u32 match ip src 10.0.0.1 action skbedit mark 0xdeadbeef
```

We can use `SO_MARK` without any coding (-m only accepts decimal)

```
sudo ping -m 1234 -c 1 10.0.0.1
```

High packet rate overloads the `ipftrace2`? Only mark the packet once per second.

```
sudo iptables -t raw -A PREROUTING -s 10.0.0.1 -m limit --limit 1/s --limit-burst 1 -j MARK --set-mark 0xdeadbeef
```

Example of using XDP metadata to set mark

https://github.com/torvalds/linux/blob/master/samples/bpf/xdp2skb_meta_kern.c

