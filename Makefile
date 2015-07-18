
target = example

objects = example.o utils.o

rebuildables = $(objects) $(target)

all: $(target)
	@echo "Success! All done."

#http://xahlee.info/UnixResource_dir/_/ldpath.html
$(target): $(objects)
	@sudo apxs -i -a -l cryptoc -l ssl -l crypto -Wc,-Wall -I . -n $(target) mod_token_auth.c $(objects)
	
# Mode 2
%.o: %.c *.h
	@g++ -O -c -I/usr/include/apache2 -I/usr/include/apr-1.0 -Wall -o $@ $<

example.o: utils.o

clean:
	@rm $(objects) $(target) || true


