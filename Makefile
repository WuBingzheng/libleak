CFLAGS = -g -O2 -Wall -fPIC -Ilibwuya
LDFLAGS = -Llibwuya

libleak.so: libleak.o symtab.o
	CFLAGS='-fPIC' make -C libwuya
	gcc -shared -o $@ $^ $(LDFLAGS) -lwuya -lpthread -ldl -lelf -lunwind -lunwind-x86_64

clean:
	rm -f libleak.so *.o
