/*
 * bptraf - eBPF traffic analyzer
 * inspired by Linux kernel xdp1 example
 * Copyright (C) 2018 Matteo Croce <mcroce@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf_util.h>

#include "common.h"

static int ifindex;

static void int_exit(int sig)
{
	bpf_set_link_xdp_fd(ifindex, -1, 0);
	exit(0);
}

static char *protocols[] = {
	[ALL] = "all",
	[IPV4] = "IPv4",
	[IPV6] = "IPv6",
	[PPPOE] = "PPPoE",
	[ICMP] = "ICMP",
	[TCP] = "TCP",
	[UDP] = "UDP",
	[SCTP] = "SCTP",
};

static void stats(int fd, int interval)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct trafdata values[nr_cpus], tot[_MAX_PROTO] = { 0 };
	int i;

	while (1) {
		unsigned key = UINT_MAX;

		sleep(interval);

		while (bpf_map_get_next_key(fd, &key, &key) != -1) {
			struct trafdata sum = { 0 };

			bpf_map_lookup_elem(fd, &key, values);
			for (i = 0; i < nr_cpus; i++) {
				sum.packets += values[i].packets;
				sum.bytes += values[i].bytes;
			}
			if (sum.packets > tot[key].packets)
				printf("%10s: %10lu kpps %10lu mbit\n",
				       protocols[key], (sum.packets - tot[key].packets) / (interval * 1000),
				       (sum.bytes - tot[key].bytes) / (interval * 125000));
			tot[key] = sum;
		}
	}
}

int main(int argc, char *argv[])
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
		.file		= "kernel.o",
	};
	struct ifreq ifr = { 0 };
	struct bpf_object *obj;
	struct bpf_map *map;
	int fd;

	fd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (fd == -1) {
		perror("fdet");
		return 1;
	}

	if (strlen(argv[optind]) >= IFNAMSIZ) {
		printf("invalid ifname '%s'\n", argv[optind]);
		return 1;
	}

	strcpy(ifr.ifr_name, argv[optind]);
	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("SIOCGIFINDEX");
		return 1;
	}
	close(fd);
	ifindex = ifr.ifr_ifindex;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &fd))
		return 1;

	if (!fd) {
		perror("load bpf file");
		return 1;
	}

	if (bpf_set_link_xdp_fd(ifindex, fd, 0) < 0) {
		printf("link set xdp fd failed\n");
		return 1;
	}

	close(fd);

	map = bpf_map__next(NULL, obj);
	if (!map) {
		perror("finding a map\n");
		return 1;
	}
	fd = bpf_map__fd(map);

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

	stats(fd, 1);

	return 0;
}
