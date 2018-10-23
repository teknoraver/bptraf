
CFLAGS := -pipe -O2 -Wall -ggdb3
KDIR := /lib/modules/$(shell uname -r)/source
CPPFLAGS := -I $(KDIR)/tools/lib
#LDFLAGS := -L $(KDIR)/tools/lib/bpf
#LDLIBS := -lbpf -lelf
LDLIBS := -lelf
BIN := kernel.o bptraf

all: $(BIN)

bptraf: bptraf.c $(KDIR)/tools/lib/bpf/libbpf.a

kernel.o: kernel.c
	clang $(CFLAGS) -target bpf -c $< -o $@

clean::
	$(RM) $(BIN)
