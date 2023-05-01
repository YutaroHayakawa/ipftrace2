#!/bin/sh

for tracer in "$@"; do
  # Launch function tracer
  ipft -v -m 1 -t $tracer -o json --enable-probe-server > /tmp/trace.txt &

  # Wait for tracer to be ready
  until nc -z 127.0.0.1 13720; do sleep 2s; done

  # Make some traffic
  ping -c 1 -m 1 127.0.0.1

  # Stop tracer
  pkill -e -TERM ipft

  # Check if the trace is valid json
  cat /tmp/trace.txt | jq -r

  # Wait for ipft to finish
  wait
done

# Run with BPF module
ipft --gen bpf-module-skeleton > extension.c

ipft -v -m 1 -o json --enable-probe-server -e extension.c > /tmp/trace.txt &

until nc -z 127.0.0.1 13720; do sleep 2s; done

ping -c 1 -m 1 127.0.0.1

pkill -e -TERM ipft

cat /tmp/trace.txt | jq -r

wait
