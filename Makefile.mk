# Makefile
all: build_crypto build_go build_rust

build_crypto:
	gcc -shared -o crypto_core/libpassword_hash.so crypto_core/password_hash.c -lsodium
	gcc -c -fPIC crypto_core/schnorr.cpp -o crypto_core/schnorr.o
	g++ -shared -o crypto_core/libschnorr.so crypto_core/schnorr.o

build_go:
	cd network && go build -buildmode=c-shared -o bindings/peer_bridge.so peer.go protocol.go

build_rust:
	cd runtime && cargo build --release
	cp runtime/target/release/libruntime.so runtime/libruntime.so

clean:
	rm crypto_core/*.so network/bindings/*.so runtime/libruntime.so