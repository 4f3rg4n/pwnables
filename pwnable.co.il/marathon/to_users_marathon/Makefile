all:
	gcc main.c -o marathon -lssl -lcrypto -lpthread
	patchelf ./marathon --set-interpreter ./ld.so
	patchelf ./marathon --replace-needed libc.so.6 ./libc.so.6
	patchelf ./marathon --replace-needed libpthread.so.0 ./libpthread.so.0
	patchelf ./marathon --replace-needed libdl.so.2 ./libdl.so.2
	patchelf ./marathon --replace-needed libcrypto.so.1.1 ./libcrypto.so.1.1
