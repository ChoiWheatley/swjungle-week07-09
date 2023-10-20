#!/bin/bash

test="tests/userprog/exec-read"
cdpath="vm/build"
command_to_run="make clean; make -j; make $test.result"

cd $cdpath

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