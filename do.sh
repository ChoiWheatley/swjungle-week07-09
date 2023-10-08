# #!/bin/bash
# tests=(
#   priority-change           #pass
#   priority-donate-one       #pass
#   priority-donate-multiple  #pass
#   priority-donate-multiple2 #pass
#   priority-donate-nest      #pass
#   priority-donate-lower     #pass
#   priority-donate-chain     #pass
#   priority-fifo             #pass
#   priority-preempt          #pass
#   priority-sema             #pass
#   priority-condvar          #pass
#   priority-donate-sema      #pass
# )
# workspace_root=$(pwd)
# log_dir="$workspace_root/log"

# if [ ! -d "$log_dir" ]; then
#   mkdir -p "$log_dir"
# fi

# cd threads
# make clean >/dev/null 2>&1
# make >/dev/null 2>&1
# cd build

# for test in ${tests[@]}; do
#   pintos -- -q run $test > "$log_dir/$test.log"
#   echo written output in "$log_dir/$test.log"
# done
cd userprog
make clean
make -j $(nproc --all)
cd build
pintos-mkdisk filesys.dsk 10
# pintos --fs-disk filesys.dsk -p tests/userprog/args-single:args-single -- -q -f run 'args-single onearg'
# pintos --fs-disk filesys.dsk -p tests/userprog/args-single:args-single -- -f run 'args-single onearg'
pintos --fs-disk filesys.dsk -p tests/userprog/fork-once:fork-once --gdb -- -f run 'fork-once'
# pintos --fs-disk -p tests/userprog/read-normal:read-normal -p ../../tests/userprog/sample.txt:sample.txt -- -q -f run read-normal
# pintos --fs-disk=10 -p tests/userprog/close-normal:close-normal -p ../../tests/userprog/sample.txt:sample.txt --gdb -- -q -f  run 'close-normal'

