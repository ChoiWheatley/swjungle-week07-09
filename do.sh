#!/bin/bash
tests=(
  priority-change #pass
  priority-donate-one #pass
  priority-donate-multiple #pass
  priority-donate-multiple2 #pass
  priority-donate-nest #pass
  priority-donate-lower #pass
  priority-donate-chain #pass
  priority-fifo #pass
  priority-preempt #pass
  priority-sema #pass
  priority-condvar #fail
  priority-donate-sema #fail
)
workspace_root=$(pwd)
log_dir="$workspace_root/log"

if [ ! -d "$log_dir" ]; then
  mkdir -p "$log_dir"
fi

cd threads
make clean >/dev/null 2>&1
make >/dev/null 2>&1
cd build

for test in ${tests[@]}; do
  pintos -- -q run $test > "$log_dir/$test.log"
  echo written output in "$log_dir/$test.log"
done
