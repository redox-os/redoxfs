UNAME := $(shell uname)

ifeq ($(UNAME),Darwin)
	FUMOUNT=umount
else ifeq ($(UNAME),FreeBSD)
	FUMOUNT=sudo umount
else
	# Detect which version of the fusermount binary is available.
	ifneq (, $(shell which fusermount3))
		FUMOUNT=fusermount3 -u
	else
		FUMOUNT=fusermount -u
	endif
endif

image.bin:
	cargo build --release --bin redoxfs-mkfs
	dd if=/dev/zero of=image.bin bs=1048576 count=1024
	target/release/redoxfs-mkfs image.bin

mount: image.bin FORCE
	mkdir -p image
	cargo build --release --bin redoxfs
	target/release/redoxfs image.bin image

unmount: FORCE
	sync
	-${FUMOUNT} image
	rm -rf image

clean: FORCE
	sync
	-${FUMOUNT} image
	rm -rf image image.bin
	cargo clean

FORCE:
