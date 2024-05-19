#!/bin/bash

# Define path to the executable
EXECUTABLE="./pkgmain"

# Define input file and expected output file
TEST_INPUT_FILE="test1.in"
EXPECTED_OUTPUT_FILE="test1.out"
ACTUAL_OUTPUT_FILE="actual_output.txt" # Temporary file for holding the actual output

# Execute the program with the 'lookall' command
$EXECUTABLE $TEST_INPUT_FILE lookall > $ACTUAL_OUTPUT_FILE

# Compare the actual output with the expected output
if diff $ACTUAL_OUTPUT_FILE $EXPECTED_OUTPUT_FILE > /dev/null; then
    echo "Test Passed: Output matches expected output."
else
    echo "Test Failed: Output does not match expected output."
    echo "Expected:"
    cat $EXPECTED_OUTPUT_FILE
    echo "Got:"
    cat $ACTUAL_OUTPUT_FILE
fi

# Clean up temporary file
rm $ACTUAL_OUTPUT_FILE

