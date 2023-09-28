cd threads
make clean
make
cd build
# pintos -- -q run priority-change      // pass
# pintos -- -q run priority-preempt     // pass
# pintos -- -q run priority-fifo        // pass
pintos -- -q run priority-donate-one