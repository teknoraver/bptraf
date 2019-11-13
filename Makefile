
CFLAGS := -pipe -Wall $(if $(DEBUG),-O0 -ggdb3,-O2)
KDIR := /lib/modules/$(shell uname -r)/source
CPPFLAGS := -I $(KDIR)/tools/lib
LDLIBS := -lelf
BIN := bptraf kernel_traf.o kernel_drop.o

all: $(BIN)

$(KDIR)/tools/lib/bpf/libbpf.a:
	$(MAKE) -C $(KDIR)/tools/lib/bpf/

bptraf: bptraf.c $(KDIR)/tools/lib/bpf/libbpf.a

kernel_%.o: kernel_%.c
	clang -O2 -Wall -g3 -c -c $< -o - -emit-llvm |llc - -o $@ -march=bpf -filetype=obj

clean::
	$(RM) $(BIN)
