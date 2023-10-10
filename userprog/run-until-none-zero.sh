#!/bin/bash

# Command to run (replace this with your command)
command_to_run="make clean; make -j; cd build; pintos -v -k -T 60 -m 20   --fs-disk=10 -p tests/filesys/base/syn-write:syn-write -p tests/filesys/base/child-syn-wrt:child-syn-wrt -- -q   -f run syn-write"

# Run the command in a loop until it returns a non-zero exit code
while true; do
    eval "$command_to_run"
    exit_code=$?
    
    if [ $exit_code -ne 0 ]; then
        echo "Command exited with non-zero status code: $exit_code"
        break
    fi

    # Optionally, you can introduce a delay between iterations
    # sleep 1  # Uncomment this line to add a 1-second delay
done