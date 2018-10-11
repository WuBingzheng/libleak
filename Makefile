CFLAGS = -g -O2 -Wall -fPIC -Ilibwuya
LDFLAGS = -Llibwuya

libleak.so: libleak.o
	CFLAGS='-fPIC' make -C libwuya
	gcc -shared -o $@ $^ $(LDFLAGS) -lwuya -lpthread -ldl

clean:
	rm -f libleak.so *.o
