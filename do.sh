# #!/bin/bash
cd vm
make clean
make -j $(nproc --all)
cd build
pintos $1 -v -k -m 20   --fs-disk=10 -p tests/vm/page-merge-par:page-merge-par -p tests/vm/child-sort:child-sort --swap-disk=10 -- -q   -f run page-merge-par
