image.bin:
	dd if=/dev/zero of=image.bin bs=1M count=1024
	cargo build --release --bin redoxfs-mkfs
	target/release/redoxfs-mkfs image.bin

mount: image.bin FORCE
	mkdir -p image
	cargo build --release --bin redoxfs
	target/release/redoxfs image.bin image

unmount: FORCE
	sync
	-fusermount -u image
	rm -rf image

clean: FORCE
	sync
	-fusermount -u image
	rm -rf image image.bin
	cargo clean

FORCE:
