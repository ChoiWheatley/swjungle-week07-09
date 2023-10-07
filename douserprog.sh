#!/bin/bash

if [ $# -lt 1 ]; then
    echo "usage: $0 <test_arg> [script=<opt>] [kernel=<opt>]"
    exit
fi

declare -A args

# loop through the arguments
for arg in "$@"; do
  # split the argument by =
  IFS="=" read -r key value <<< "$arg"
  # assign the key and value to the array
  args[$key]=$value
done

workspace_root=$(pwd)
log_dir="$workspace_root/log"
test_arg=$1
script_opt=${args["script"]}
kernel_opt=${args["kernel"]}
log_file="$log_dir/$test_arg.log"

if [ ! -d "$log_dir" ]; then
    mkdir -p "$log_dir"
fi

cd userprog
make clean >/dev/null 2>&1
make -j $(nproc --all) >/dev/null 2>&1
cd build

pintos $script_opt --fs-disk=10 -p tests/userprog/$test_arg:$test_arg -- -q -f run "$test_arg $kernel_opt"

echo written output in "$log_file"