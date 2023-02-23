PROG = project02
OBJS = project02.o sha256.o passwords.o
TMP = $(PROG) $(OBJS) dict.txt

%.o: %.c
	gcc -c -g -o $@ $<

$(PROG): $(OBJS)
	gcc -g -o $@ $^

clean:
	rm -rf $(TMP)
