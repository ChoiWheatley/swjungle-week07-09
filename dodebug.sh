cd threads
make clean
make
cd build
pintos --gdb -- $1 -q run $2
