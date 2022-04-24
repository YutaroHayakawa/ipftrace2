#!/bin/sh

for tracer in "$@"; do
  # Launch function tracer
  ipft -m 1 -t $tracer -o json --enable-probe-server > /tmp/trace.txt &

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
