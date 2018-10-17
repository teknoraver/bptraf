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

/* This one is to workaround the following compile error
 *
 * In file included from kernel.c:2:
 * In file included from /usr/lib64/clang/6.0.1/include/stdint.h:63:
 * In file included from /usr/include/stdint.h:26:
 * In file included from /usr/include/bits/libc-header-start.h:33:
 * In file included from /usr/include/features.h:452:
 * /usr/include/gnu/stubs.h:7:11: fatal error: 'gnu/stubs-32.h' file not found
 * # include <gnu/stubs-32.h>
 */

#define __x86_64__

#include <stdint.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include "common.h"

/*
 * Sample XDP program, create statistics about interface traffic.
 * compile it with:
 * 	clang -O3 -target bpf -c kernel.c -o kernel.o
 * attach it to a device with:
 * 	ip link set dev lo xdp object kernel.o verbose
 */

#define SEC(NAME) __attribute__((section(NAME), used))

#define L2L3SHIFT (sizeof(((struct ethhdr *)0)->h_proto) * 8)

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int inner_map_idx;
	unsigned int numa_node;
};

struct bpf_map_def SEC("maps") traf = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(unsigned),
	.value_size = sizeof(struct trafdata),
	.max_entries = _MAX_PROTO,
};

static void *(*bpf_map_lookup_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_lookup_elem;

static void inc_stats(unsigned key, int len)
{
	struct trafdata *val = bpf_map_lookup_elem(&traf, &key);

	if (val) {
		val->packets++;
		val->bytes += len;
	}
}

static enum protocols parse_eth(uint16_t type)
{
	switch (type) {
	case ETH_P_ARP:
		/* fallthrough */
	case ETH_P_IP:
		return IPV4;
	case ETH_P_IPV6:
		return IPV6;
	case ETH_P_PPP_DISC:
		/* fallthrough */
	case ETH_P_PPP_SES:
		return PPPOE;
	}

	return 0;
}

static enum protocols parse_ip(uint8_t proto)
{
	switch (proto) {
	case IPPROTO_ICMP:
		return ICMP;
	case IPPROTO_TCP:
		return TCP;
	case IPPROTO_UDP:
		return UDP;
	case IPPROTO_SCTP:
		return SCTP;
	}

	return 0;
}

SEC("prog")
int xdp_main(struct xdp_md *ctx)
{
	void *data_end = (void *)(uintptr_t)ctx->data_end;
	void *data = (void *)(uintptr_t)ctx->data;
	const size_t plen = data_end - data + 1;
	uint16_t ethproto;
	uint8_t ipproto = 0;
	size_t l3len;
	struct ethhdr *eth = data;

	/* sanity check needed by the eBPF verifier */
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	ethproto = __constant_ntohs(eth->h_proto);

	/* key 0 represents all packets */
	inc_stats(ALL, plen);

	if (ethproto)
		inc_stats(parse_eth(ethproto), plen - sizeof(*eth));

	switch (ethproto) {
	case ETH_P_IP: {
		struct iphdr *iph = (struct iphdr *)(eth + 1);

		if ((void *)(iph + 1) > data_end)
			break;

		ipproto = parse_ip(iph->protocol);
		l3len = sizeof(*iph);
		break;
	}
	case ETH_P_IPV6: {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);

		if ((void *)(ip6h + 1) > data_end)
			break;

		ipproto = parse_ip(ip6h->nexthdr);
		l3len = sizeof(*ip6h);
		break;
	}
	case ETH_P_PPP_DISC:
		/* fallthrough */
	case ETH_P_PPP_SES:
		/* fallthrough */
	case ETH_P_ARP:
		break;
	default:
		return XDP_PASS;
	}

	if (ipproto)
		inc_stats(ipproto, plen - l3len);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
