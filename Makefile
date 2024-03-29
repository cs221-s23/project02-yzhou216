PROG = project02
OBJS = project02.o sha256.o
TMP = $(PROG) $(OBJS) *.txt

%.o: %.c
	gcc -c -g -o $@ $<

$(PROG): $(OBJS)
	gcc -g -o $@ $^

clean:
	rm -rf $(TMP)
