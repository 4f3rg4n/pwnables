all:
	gcc -Wall -Werror main.c game.c safe_storage.c processor.c auth.c tlv.c -g -o warrior
	patchelf ./warrior --set-interpreter ./ld-2.23.so
	patchelf ./warrior --replace-needed libc.so.6 ./libc-2.23.so
clean:
	rm warrior
