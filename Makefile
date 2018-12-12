all: waCrypto.html

waCrypto.html: waCrypto.cc
	emcc -L./openssl -I./openssl/include waCrypto.cc -s WASM=1 -o waCrypto.html -lssl -lcrypto --emrun -s EXPORTED_FUNCTIONS='["_JSAESEncryptGCM", "_JSAESDecryptGCM"]' -s EXTRA_EXPORTED_RUNTIME_METHODS='["ccall", "cwrap"]'

clean:
	rm waCrypto.html waCrypto.wasm waCrypto.js 