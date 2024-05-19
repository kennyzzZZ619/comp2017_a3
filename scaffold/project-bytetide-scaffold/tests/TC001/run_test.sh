#!/bin/bash

# Define path to the executable
EXECUTABLE="./pkgmain"

# Declare an array of test cases
declare -a TESTS=("test1" "test2")

# Loop through all test cases
for TEST_PATH in "${TESTS[@]}"
do
    TEST_INPUT_FILE="${TEST_PATH}.in"
    EXPECTED_OUTPUT_FILE="${TEST_PATH}.out"

    # Execute the program with the lookall flag
    ACTUAL_OUTPUT=$(mktemp)  # Create a temporary file to hold the output
    $EXECUTABLE $TEST_INPUT_FILE lookall > $ACTUAL_OUTPUT

    # Compare the actual output with the expected output
    if diff $ACTUAL_OUTPUT $EXPECTED_OUTPUT_FILE > /dev/null; then
        echo "Test Passed for $(basename $TEST_INPUT_FILE): Output matches expected output."
        rm $ACTUAL_OUTPUT  # Clean up temporary file
    else
        echo "Test Failed for $(basename $TEST_INPUT_FILE): Output does not match expected output."
        echo "Expected:"
        cat $EXPECTED_OUTPUT_FILE
        echo "Got:"
        cat $ACTUAL_OUTPUT
        rm $ACTUAL_OUTPUT  # Clean up temporary file
        exit 1  
    fi
done

exit 0 


