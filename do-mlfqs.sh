cd threads
make clean >/dev/null 2>&1
make >/dev/null 2>&1
cd build

pintos $2 -- -mlfqs -q run $1