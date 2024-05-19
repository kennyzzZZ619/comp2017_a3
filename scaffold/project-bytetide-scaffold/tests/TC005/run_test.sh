#!/bin/bash

# Define path to the executable
EXECUTABLE="./pkgmain"

# Define input files and expected output files
declare -a INPUT_FILES=("test1.in" "test2.in")
declare -a OUTPUT_FILES=("test1.out" "test2.out")

# Loop through all test files
for i in 0 1
do
    TEST_INPUT_FILE=${INPUT_FILES[$i]}
    EXPECTED_OUTPUT_FILE=${OUTPUT_FILES[$i]}
    ACTUAL_OUTPUT_FILE="actual_output_$i.txt" 
    # Execute the program
    $EXECUTABLE $TEST_INPUT_FILE -file_check > $ACTUAL_OUTPUT_FILE

    # Compare the actual output with the expected output
    if diff $ACTUAL_OUTPUT_FILE $EXPECTED_OUTPUT_FILE > /dev/null; then
        echo "Test Passed for $(basename $TEST_INPUT_FILE): Output matches expected output."
    else
        echo "Test Failed for $(basename $TEST_INPUT_FILE): Output does not match expected output."
        echo "Expected:"
        cat $EXPECTED_OUTPUT_FILE
        echo "Got:"
        cat $ACTUAL_OUTPUT_FILE
    fi


    rm $ACTUAL_OUTPUT_FILE
done

