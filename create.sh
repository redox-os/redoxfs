#!/bin/bash
rm -f test.bin

cargo run --bin redoxfs-utility test.bin << "EOF"

mk a_file
mkdir a_directory
cd a_directory

ed b_file
B FILE
.

cat b_file

ed c_file
C FILE
.

cat c_file

ls

exit

EOF
