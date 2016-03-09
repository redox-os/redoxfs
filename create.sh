#!/bin/bash
rm -f ../../filesystem/etc/redoxfs.bin

cargo run --bin redoxfs-utility ../../filesystem/etc/redoxfs.bin << "EOF"

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
