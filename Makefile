CFLAGS = -g -O2 -Wall -fPIC -I../futures_engine/libwuya
LDFLAGS = -L../futures_engine/libwuya

libmemleak.so: libmemleak.o symtab.o
	gcc -shared -o $@ $^ $(LDFLAGS) -lwuya -lpthread -ldl -lelf -lunwind -lunwind-x86_64
