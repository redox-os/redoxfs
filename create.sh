#!/bin/bash
rm -f ../../filesystem/etc/redoxfs.bin
cargo run ../../filesystem/etc/redoxfs.bin <<-EOF
    mk a_file
    mkdir a_directory
    cd a_directory
    mk b_file
    mk c_file
    exit
EOF
