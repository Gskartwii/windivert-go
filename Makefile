COPTS= -shared -Wall -Wno-pointer-to-int-cast -O2 -Iinclude/ -Wl,--enable-stdcall-fixup -Wl,--entry=_WinDivertDllEntry -m32
CC= gcc
all:
	gofmt -e -s -w .
	$(CC) $(COPTS) -o windivert/windivert.o -c windivert/windivert.c
	$(CC) $(COPTS) -o libwindivert.dll windivert/windivert.o windivert/windivert.def -nostdlib -lgcc -lkernel32 -ladvapi32