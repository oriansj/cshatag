cshatag: cshatag.c
	gcc cshatag.c -l crypto -o cshatag

debug: cshatag.c
	gcc -ggdb cshatag.c -l crypto -o cshatag

install: cshatag
	cp -v cshatag /usr/local/bin
	mkdir -v /usr/local/share/man/man1 2> /dev/null || true
	cp -v cshatag.1 /usr/local/share/man/man1

clean: cshatag
	rm -f cshatag
