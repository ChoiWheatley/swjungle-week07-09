cd threads
make clean
make
cd build
pintos -- -q run priority-change      # pass
pintos -- -q run priority-donate-one  # pass
pintos -- -q run priority-donate-multiple  # pass
pintos -- -q run priority-donate-multiple2  # pass
pintos -- -q run priority-donate-nest  # fail
pintos -- -q run priority-donate-sema  # fail
pintos -- -q run priority-donate-lower  # pass
pintos -- -q run priority-donate-chain  # fail
pintos -- -q run priority-fifo        # pass
pintos -- -q run priority-preempt     # pass
pintos -- -q run priority-sema  # pass
pintos -- -q run priority-condvar  # fail
