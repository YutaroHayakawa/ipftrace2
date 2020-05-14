#!/bin/bash

ret=0

for t in $(ls *.lua); do
  ipft -m 0xdeadbeef -s ../tests/write_all_registers.lua --test
  stat=$?
  if [ $stat = "0" ]; then
    echo $(printf "%s: [OK]" $t)
  else
    echo $(printf "%s: [Failed]" $t)
    ret=1
  fi
done

exit $ret
