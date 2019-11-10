# bptraf - eBPF based traffic analyzer

`bptraf` is a simple traffic analyzer which uses *XDP* to count packets.  
bptraf is fast because the packet counting is done by an eBPF program loaded into the kernel via *XDP*. The userspace part just fetches the data once a second, without copying data as other AF\_PACKET or libpcap based tools do.  
The data is shared via the kernel and the  userspace via an eBPF map. To be precise, one map per CPU is used, so no locking is needed to populate the map, so `bptraf` can handle dozens of millions of packets per seconds on a modern CPU.

## compiling
Compiling bptraf is straightforward, just `make` as usual. The only tricky part is having a recent `libbpf.a` library to link against.  
If you have a source kernel tree, compile it with:
```
matteo@raver:~/src/linux$ cd tools/lib/bpf/
matteo@raver:~/src/linux/tools/lib/bpf$ make

Auto-detecting system features:
...                        libelf: [ on  ]
...                           bpf: [ on  ]

[...]
  LINK     libbpf.a
```
Most probably you will need the libbpf devel package fro your distro.  
When you have libbpf.a, just compile `bptraf` by passing the kernel source root directory as KDIR:
```
matteo@raver:~/src/bptraf$ make KDIR=../linux
cc -pipe -O2 -Wall -ggdb3 -I ../linux/tools/lib   bptraf.c ../linux/tools/lib/bpf/libbpf.a  -lelf -o bptraf
clang -O2 -Wall -ggdb3 -c -c kernel_traf.c -o - -emit-llvm |llc - -o kernel_traf.o -march=bpf -filetype=obj
clang -O2 -Wall -ggdb3 -c -c kernel_drop.c -o - -emit-llvm |llc - -o kernel_drop.o -march=bpf -filetype=obj
```
Clang is needed to compile the kernel part in eBPF bytecode.

## usage
Just specify an interface name, and `bptraf` will start showing traffic statistics:
```
# bptraf wlp3s0
       all: 12.88 Kpps 154.9 Mbps
      IPv4: 12.88 Kpps 153.4 Mbps
       TCP: 12.88 Kpps 152.8 Mbps
       UDP: 1 pps 1823 bps
       all: 37.19 Kpps 448.1 Mbps
      IPv4: 37.20 Kpps 444.0 Mbps
       TCP: 37.20 Kpps 442.4 Mbps
       all: 36.20 Kpps 436.3 Mbps
      IPv4: 36.19 Kpps 432.1 Mbps
       TCP: 36.18 Kpps 430.3 Mbps
```
An `-i INT` interval will change the collecting interval time, default is one second.  
`bptraf -d` will drop all the packets after counting them. To maximize capture speed, only the total packets and byte count is shown (no per protocol stats), because accessing the packet content will most likely cause a cache miss.  
This test was made on an ARM Cortex-A72 machine:
```
# bptraf eth0 -d
       all: 12.87 Mpps 6073 Mbps
       all: 12.86 Mpps 6072 Mbps
       all: 12.86 Mpps 6071 Mbps
       all: 12.86 Mpps 6072 Mbps
       all: 12.86 Mpps 6071 Mbps
       all: 12.86 Mpps 6072 Mbps
       all: 12.86 Mpps 6071 Mbps
       all: 12.86 Mpps 6071 Mbps
```

## license
`bptraf` was inspired by the kernel bpf samples, it's fully GPLv3
