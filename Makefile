CFLAGS = -g -O2 -Wall -fPIC -Ilibwuya
LDFLAGS = -Llibwuya

libleak.so: libleak.o
	CFLAGS='-fPIC' make -C libwuya
	$(CC) -shared -o $@ $^ $(LDFLAGS) -lwuya -lpthread -ldl -lbacktrace

clean:
	make -C libwuya clean
	rm -f libleak.so *.o
