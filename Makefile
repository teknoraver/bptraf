
CFLAGS := -pipe -O2 -Wall -ggdb3
KDIR := /lib/modules/$(shell uname -r)/source
CPPFLAGS := -I $(KDIR)/tools/lib
#LDFLAGS := -L $(KDIR)/tools/lib/bpf
#LDLIBS := -lbpf -lelf
LDLIBS := -lelf
BIN := bptraf kernel_traf.o kernel_drop.o

all: $(BIN)

bptraf: bptraf.c $(KDIR)/tools/lib/bpf/libbpf.a

kernel_%.o: kernel_%.c
	clang -O2 -Wall -ggdb3 -c -c $< -o - -emit-llvm |llc - -o $@ -march=bpf -filetype=obj

clean::
	$(RM) $(BIN)
