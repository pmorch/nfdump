/*
 *  This file is part of the nfdump project.
 *
 *  Copyright (c) 2004, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *   * Neither the name of SWITCH nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 *  
 *  $Author: peter $
 *
 *  $Id: nftest.c 70 2006-05-17 08:38:01Z peter $
 *
 *  $LastChangedRevision: 70 $
 *	
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>
#include <stdlib.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nfdump.h"
#include "nftree.h"
#include "nffile.h"
#include "nf_common.h"
#include "util.h"

/* Global Variables */
extern char 	*CurrentIdent;

FilterEngine_data_t	*Engine;
uint32_t			byte_limit, packet_limit;
int 				byte_mode, packet_mode;

#define TCP	6
#define UDP 17

int check_filter_block(char *filter, master_record_t *flow_record, int expect);

void check_offset(char *text, pointer_addr_t offset, pointer_addr_t expect);

int check_filter_block(char *filter, master_record_t *flow_record, int expect) {
int ret, i;
uint64_t	*block = (uint64_t *)flow_record;

	Engine = CompileFilter(filter);
	if ( !Engine ) {
		exit(254);
	}

	Engine->nfrecord = (uint64_t *)flow_record;
	ret =  (*Engine->FilterEngine)(Engine);
	if ( ret == expect ) {
		printf("Success: Startnode: %i Numblocks: %i Extended: %i Filter: '%s'\n", Engine->StartNode, nblocks(), Engine->Extended, filter);
	} else {
		printf("**** FAILED **** Startnode: %i Numblocks: %i Extended: %i Filter: '%s'\n", Engine->StartNode, nblocks(), Engine->Extended, filter);
		DumpList(Engine);
		printf("Expected: %i, Found: %i\n", expect, ret);
		printf("Record:\n");
		for(i=0; i<=10; i++) {
			printf("%3i %.16llx\n", i, block[i]);
		}
		if ( Engine->IdentList ) {
			printf("Current Ident: %s, Ident 0 %s\n", CurrentIdent, Engine->IdentList[0]);
		}
		exit(255);
	}
	return (ret == expect);
}

void check_offset(char *text, pointer_addr_t offset, pointer_addr_t expect) {

	if ( offset == expect ) {
		printf("Success: %s: %u\n", text, expect);
	} else {
		printf("**** FAILED **** %s expected %u, evaluated %u\n", text, expect, offset);
		// useless to continue
		exit(255);
	}
}

int main(int argc, char **argv) {
master_record_t flow_record;
uint64_t *blocks, l;
uint32_t size, in[2];
time_t	now;
int ret;
value64_t	v;

    if ( sizeof(struct in_addr) != sizeof(uint32_t) ) {
#ifdef HAVE_SIZE_T_Z_FORMAT
        printf("**** FAILED **** Size struct in_addr %zu != sizeof(uint32_t)\n", sizeof(struct in_addr));
#else 
        printf("**** FAILED **** Size struct in_addr %lu != sizeof(uint32_t)\n", (unsigned long)sizeof(struct in_addr));
#endif
		exit(255);
    }

	l = 0x200000000LL;
	v.val.val64 = l;
	in[0] = v.val.val32[0];
	in[1] = v.val.val32[1];
	ret = memcmp(in, &l, sizeof(uint64_t));
	if ( ret != 0 ) {
        printf("**** FAILED **** val32/64 union check failed!\n" );
		exit(255);
	}
	size = sizeof(common_record_t) - sizeof(uint8_t[4]);
	memset((void *)&flow_record, 0, sizeof(master_record_t));
	blocks = (uint64_t *)&flow_record;

	check_offset("First    Offset", (unsigned int)((pointer_addr_t)&flow_record.first  -  (pointer_addr_t)blocks), BYTE_OFFSET_first);
	check_offset("Common   Offset", (unsigned int)((pointer_addr_t)&flow_record.fill  -  (pointer_addr_t)blocks), size);
	check_offset("Src AS   Offset", (unsigned int)((pointer_addr_t)&flow_record.srcas  -  (pointer_addr_t)&blocks[OffsetAS]), 0);
	check_offset("Dst AS   Offset", (unsigned int)((pointer_addr_t)&flow_record.dstas  -  (pointer_addr_t)&blocks[OffsetAS]), 2);
	check_offset("Src Port Offset", (unsigned int)((pointer_addr_t)&flow_record.srcport - (pointer_addr_t)&blocks[OffsetPort]), 4);
	check_offset("Dst Port Offset", (unsigned int)((pointer_addr_t)&flow_record.dstport - (pointer_addr_t)&blocks[OffsetPort]), 6);
	check_offset("Dir      Offset", (unsigned int)((pointer_addr_t)&flow_record.dir     - (pointer_addr_t)&blocks[OffsetDir]), 4);
	check_offset("Flags    Offset", (unsigned int)((pointer_addr_t)&flow_record.tcp_flags    - (pointer_addr_t)&blocks[OffsetFlags]), 5);
	check_offset("Protocol Offset", (unsigned int)((pointer_addr_t)&flow_record.prot    - (pointer_addr_t)&blocks[OffsetProto]), 6);
	check_offset("tos      Offset", (unsigned int)((pointer_addr_t)&flow_record.tos     - (pointer_addr_t)&blocks[OffsetTos]), 7);

#ifdef HAVE_SIZE_T_Z_FORMAT
	printf("Pointer Size : %zu\n", sizeof(blocks));
	printf("Time_t  Size : %zu\n", sizeof(now));
	printf("int     Size : %zu\n", sizeof(int));
	printf("long    Size : %zu\n", sizeof(long));
#else
	printf("Pointer Size : %lu\n", (unsigned long)sizeof(blocks));
	printf("Time_t  Size : %lu\n", (unsigned long)sizeof(now));
	printf("int     Size : %lu\n", (unsigned long)sizeof(int));
	printf("long    Size : %lu\n", (unsigned long)sizeof(long));
#endif

	flow_record.flags	 = 0;
	ret = check_filter_block("ipv4", &flow_record, 1);
	flow_record.flags	 = 2;
	ret = check_filter_block("ipv4", &flow_record, 1);
	ret = check_filter_block("ipv6", &flow_record, 0);
	flow_record.flags	 = 1;
	ret = check_filter_block("ipv4", &flow_record, 0);
	ret = check_filter_block("ipv6", &flow_record, 1);
	flow_record.flags	 = 7;
	ret = check_filter_block("ipv4", &flow_record, 0);
	ret = check_filter_block("ipv6", &flow_record, 1);


	flow_record.prot	 = TCP;
	ret = check_filter_block("any", &flow_record, 1);
	ret = check_filter_block("not any", &flow_record, 0);
	ret = check_filter_block("tcp", &flow_record, 1);
	ret = check_filter_block("proto tcp", &flow_record, 1);
	ret = check_filter_block("proto udp", &flow_record, 0);
	flow_record.prot = UDP;
	ret = check_filter_block("proto tcp", &flow_record, 0);
	ret = check_filter_block("proto udp", &flow_record, 1);
	flow_record.prot = 50;
	ret = check_filter_block("proto esp", &flow_record, 1);
	ret = check_filter_block("proto ah", &flow_record, 0);
	flow_record.prot = 51;
	ret = check_filter_block("proto ah", &flow_record, 1);
	flow_record.prot = 46;
	ret = check_filter_block("proto rsvp", &flow_record, 1);
	flow_record.prot = 47;
	ret = check_filter_block("proto gre", &flow_record, 1);
	ret = check_filter_block("proto 47", &flow_record, 1);
	ret = check_filter_block("proto 42", &flow_record, 0);

	inet_pton(PF_INET6, "fe80::2110:abcd:1234:5678", flow_record.v6.srcaddr);
	inet_pton(PF_INET6, "fe80::1104:fedc:4321:8765", flow_record.v6.dstaddr);
	flow_record.v6.srcaddr[0] = ntohll(flow_record.v6.srcaddr[0]);
	flow_record.v6.srcaddr[1] = ntohll(flow_record.v6.srcaddr[1]);
	flow_record.v6.dstaddr[0] = ntohll(flow_record.v6.dstaddr[0]);
	flow_record.v6.dstaddr[1] = ntohll(flow_record.v6.dstaddr[1]);
	ret = check_filter_block("src ip fe80::2110:abcd:1234:5678", &flow_record, 1);
	ret = check_filter_block("src ip fe80::2110:abcd:1234:5679", &flow_record, 0);
	ret = check_filter_block("src ip fe80::2111:abcd:1234:5678", &flow_record, 0);
	ret = check_filter_block("dst ip fe80::1104:fedc:4321:8765", &flow_record, 1);
	ret = check_filter_block("dst ip fe80::1104:fedc:4321:8766", &flow_record, 0);
	ret = check_filter_block("dst ip fe80::1105:fedc:4321:8765", &flow_record, 0);
	ret = check_filter_block("ip fe80::2110:abcd:1234:5678", &flow_record, 1);
	ret = check_filter_block("ip fe80::1104:fedc:4321:8765", &flow_record, 1);
	ret = check_filter_block("ip fe80::2110:abcd:1234:5679", &flow_record, 0);
	ret = check_filter_block("ip fe80::1104:fedc:4321:8766", &flow_record, 0);
	ret = check_filter_block("not ip fe80::2110:abcd:1234:5678", &flow_record, 0);
	ret = check_filter_block("not ip fe80::2110:abcd:1234:5679", &flow_record, 1);

	inet_pton(PF_INET6, "fe80::2110:abcd:1234:0", flow_record.v6.srcaddr);
	flow_record.v6.srcaddr[0] = ntohll(flow_record.v6.srcaddr[0]);
	flow_record.v6.srcaddr[1] = ntohll(flow_record.v6.srcaddr[1]);
	ret = check_filter_block("src net fe80::2110:abcd:1234:0/112", &flow_record, 1);

	inet_pton(PF_INET6, "fe80::2110:abcd:1234:ffff", flow_record.v6.srcaddr);
	flow_record.v6.srcaddr[0] = ntohll(flow_record.v6.srcaddr[0]);
	flow_record.v6.srcaddr[1] = ntohll(flow_record.v6.srcaddr[1]);
	ret = check_filter_block("src net fe80::2110:abcd:1234:0/112", &flow_record, 1);

	inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", flow_record.v6.srcaddr);
	flow_record.v6.srcaddr[0] = ntohll(flow_record.v6.srcaddr[0]);
	flow_record.v6.srcaddr[1] = ntohll(flow_record.v6.srcaddr[1]);
	ret = check_filter_block("src net fe80::2110:abcd:1234:0/112", &flow_record, 0);
	ret = check_filter_block("src net fe80::0/16", &flow_record, 1);
	ret = check_filter_block("src net fe81::0/16", &flow_record, 0);

	flow_record.v6.srcaddr[0] = 0;
	flow_record.v6.srcaddr[1] = 0;

	inet_pton(PF_INET6, "fe80::2110:abcd:1234:0", flow_record.v6.dstaddr);
	flow_record.v6.dstaddr[0] = ntohll(flow_record.v6.dstaddr[0]);
	flow_record.v6.dstaddr[1] = ntohll(flow_record.v6.dstaddr[1]);
	ret = check_filter_block("dst net fe80::2110:abcd:1234:0/112", &flow_record, 1);

	inet_pton(PF_INET6, "fe80::2110:abcd:1234:ffff", flow_record.v6.dstaddr);
	flow_record.v6.dstaddr[0] = ntohll(flow_record.v6.dstaddr[0]);
	flow_record.v6.dstaddr[1] = ntohll(flow_record.v6.dstaddr[1]);
	ret = check_filter_block("dst net fe80::2110:abcd:1234:0/112", &flow_record, 1);

	inet_pton(PF_INET6, "fe80::2110:abcd:1235:ffff", flow_record.v6.dstaddr);
	flow_record.v6.dstaddr[0] = ntohll(flow_record.v6.dstaddr[0]);
	flow_record.v6.dstaddr[1] = ntohll(flow_record.v6.dstaddr[1]);
	ret = check_filter_block("dst net fe80::2110:abcd:1234:0/112", &flow_record, 0);
	ret = check_filter_block("dst net fe80::0/16", &flow_record, 1);
	ret = check_filter_block("not dst net fe80::0/16", &flow_record, 0);
	ret = check_filter_block("dst net fe81::0/16", &flow_record, 0);
	ret = check_filter_block("not dst net fe81::0/16", &flow_record, 1);


	/* 172.32.7.16 => 0xac200710
	 * 10.10.10.11 => 0x0a0a0a0b
	 */
	flow_record.v6.srcaddr[0] = 0;
	flow_record.v6.srcaddr[1] = 0;
	flow_record.v6.dstaddr[0] = 0;
	flow_record.v6.dstaddr[1] = 0;
	flow_record.v4.srcaddr = 0xac200710;
	flow_record.v4.dstaddr = 0x0a0a0a0b;
	ret = check_filter_block("src ip 172.32.7.16", &flow_record, 1);
	ret = check_filter_block("src ip 172.32.7.15", &flow_record, 0);
	ret = check_filter_block("dst ip 10.10.10.11", &flow_record, 1);
	ret = check_filter_block("dst ip 10.10.10.10", &flow_record, 0);
	ret = check_filter_block("ip 172.32.7.16", &flow_record, 1);
	ret = check_filter_block("ip 10.10.10.11", &flow_record, 1);
	ret = check_filter_block("ip 172.32.7.17", &flow_record, 0);
	ret = check_filter_block("ip 10.10.10.12", &flow_record, 0);
	ret = check_filter_block("not ip 172.32.7.16", &flow_record, 0);
	ret = check_filter_block("not ip 172.32.7.17", &flow_record, 1);

	ret = check_filter_block("src host 172.32.7.16", &flow_record, 1);
	ret = check_filter_block("src host 172.32.7.15", &flow_record, 0);
	ret = check_filter_block("dst host 10.10.10.11", &flow_record, 1);
	ret = check_filter_block("dst host 10.10.10.10", &flow_record, 0);
	ret = check_filter_block("host 172.32.7.16", &flow_record, 1);
	ret = check_filter_block("host 10.10.10.11", &flow_record, 1);
	ret = check_filter_block("host 172.32.7.17", &flow_record, 0);
	ret = check_filter_block("host 10.10.10.12", &flow_record, 0);
	ret = check_filter_block("not host 172.32.7.16", &flow_record, 0);
	ret = check_filter_block("not host 172.32.7.17", &flow_record, 1);

	flow_record.srcport = 63;
	flow_record.dstport = 255;
	ret = check_filter_block("src port 63", &flow_record, 1);
	ret = check_filter_block("dst port 255", &flow_record, 1);
	ret = check_filter_block("port 63", &flow_record, 1);
	ret = check_filter_block("port 255", &flow_record, 1);
	ret = check_filter_block("src port 64", &flow_record, 0);
	ret = check_filter_block("dst port 258", &flow_record, 0);
	ret = check_filter_block("port 64", &flow_record, 0);
	ret = check_filter_block("port 258", &flow_record, 0);

	ret = check_filter_block("src port = 63", &flow_record, 1);
	ret = check_filter_block("src port == 63", &flow_record, 1);
	ret = check_filter_block("src port eq 63", &flow_record, 1);
	ret = check_filter_block("src port > 62", &flow_record, 1);
	ret = check_filter_block("src port gt 62", &flow_record, 1);
	ret = check_filter_block("src port > 63", &flow_record, 0);
	ret = check_filter_block("src port < 64", &flow_record, 1);
	ret = check_filter_block("src port lt 64", &flow_record, 1);
	ret = check_filter_block("src port < 63", &flow_record, 0);

	ret = check_filter_block("dst port = 255", &flow_record, 1);
	ret = check_filter_block("dst port == 255", &flow_record, 1);
	ret = check_filter_block("dst port eq 255", &flow_record, 1);
	ret = check_filter_block("dst port > 254", &flow_record, 1);
	ret = check_filter_block("dst port gt 254", &flow_record, 1);
	ret = check_filter_block("dst port > 255", &flow_record, 0);
	ret = check_filter_block("dst port < 256", &flow_record, 1);
	ret = check_filter_block("dst port lt 256", &flow_record, 1);
	ret = check_filter_block("dst port < 255", &flow_record, 0);

	flow_record.srcas = 123;
	flow_record.dstas = 456;
	ret = check_filter_block("src as 123", &flow_record, 1);
	ret = check_filter_block("dst as 456", &flow_record, 1);
	ret = check_filter_block("as 123", &flow_record, 1);
	ret = check_filter_block("as 456", &flow_record, 1);
	ret = check_filter_block("src as 124", &flow_record, 0);
	ret = check_filter_block("dst as 457", &flow_record, 0);
	ret = check_filter_block("as 124", &flow_record, 0);
	ret = check_filter_block("as 457", &flow_record, 0);

	ret = check_filter_block("src net 172.32/16", &flow_record, 1);
	ret = check_filter_block("src net 172.32.7/24", &flow_record, 1);
	ret = check_filter_block("src net 172.32.7.0/27", &flow_record, 1);
	ret = check_filter_block("src net 172.32.7.0/28", &flow_record, 0);
	ret = check_filter_block("src net 172.32.7.0 255.255.255.0", &flow_record, 1);
	ret = check_filter_block("src net 172.32.7.0 255.255.255.240", &flow_record, 0);

	ret = check_filter_block("dst net 10.10/16", &flow_record, 1);
	ret = check_filter_block("dst net 10.10.10/24", &flow_record, 1);
	ret = check_filter_block("dst net 10.10.10.0/28", &flow_record, 1);
	ret = check_filter_block("dst net 10.10.10.0/29", &flow_record, 0);
	ret = check_filter_block("dst net 10.10.10.0 255.255.255.240", &flow_record, 1);
	ret = check_filter_block("dst net 10.10.10.0 255.255.255.248", &flow_record, 0);

	ret = check_filter_block("net 172.32/16", &flow_record, 1);
	ret = check_filter_block("net 172.32.7/24", &flow_record, 1);
	ret = check_filter_block("net 172.32.7.0/27", &flow_record, 1);
	ret = check_filter_block("net 172.32.7.0/28", &flow_record, 0);
	ret = check_filter_block("net 172.32.7.0 255.255.255.0", &flow_record, 1);
	ret = check_filter_block("net 172.32.7.0 255.255.255.240", &flow_record, 0);

	ret = check_filter_block("net 10.10/16", &flow_record, 1);
	ret = check_filter_block("net 10.10.10/24", &flow_record, 1);
	ret = check_filter_block("net 10.10.10.0/28", &flow_record, 1);
	ret = check_filter_block("net 10.10.10.0/29", &flow_record, 0);
	ret = check_filter_block("net 10.10.10.0 255.255.255.240", &flow_record, 1);
	ret = check_filter_block("net 10.10.10.0 255.255.255.240", &flow_record, 1);
	ret = check_filter_block("net 10.10.10.0 255.255.255.248", &flow_record, 0);

	ret = check_filter_block("src ip 172.32.7.16 or src ip 172.32.7.15", &flow_record, 1);
	ret = check_filter_block("src ip 172.32.7.15 or src ip 172.32.7.16", &flow_record, 1);
	ret = check_filter_block("src ip 172.32.7.15 or src ip 172.32.7.14", &flow_record, 0);
	ret = check_filter_block("src ip 172.32.7.16 and dst ip 10.10.10.11", &flow_record, 1);
	ret = check_filter_block("src ip 172.32.7.15 and dst ip 10.10.10.11", &flow_record, 0);
	ret = check_filter_block("src ip 172.32.7.16 and dst ip 10.10.10.12", &flow_record, 0);

	flow_record.tcp_flags = 1;
	ret = check_filter_block("flags F", &flow_record, 1);
	ret = check_filter_block("flags S", &flow_record, 0);
	ret = check_filter_block("flags R", &flow_record, 0);
	ret = check_filter_block("flags P", &flow_record, 0);
	ret = check_filter_block("flags A", &flow_record, 0);
	ret = check_filter_block("flags U", &flow_record, 0);
	ret = check_filter_block("flags X", &flow_record, 0);

	flow_record.tcp_flags = 2; // flags S
	ret = check_filter_block("flags S", &flow_record, 1);
	flow_record.tcp_flags = 4;
	ret = check_filter_block("flags R", &flow_record, 1);
	flow_record.tcp_flags = 8;
	ret = check_filter_block("flags P", &flow_record, 1);
	flow_record.tcp_flags = 16;
	ret = check_filter_block("flags A", &flow_record, 1);
	flow_record.tcp_flags = 32;
	ret = check_filter_block("flags U", &flow_record, 1);
	flow_record.tcp_flags = 63;
	ret = check_filter_block("flags X", &flow_record, 1);

	ret = check_filter_block("not flags RF", &flow_record, 0);

	flow_record.tcp_flags = 3;	// flags SF
	ret = check_filter_block("flags SF", &flow_record, 1);
	ret = check_filter_block("flags 3", &flow_record, 1);
	ret = check_filter_block("flags S and not flags AR", &flow_record, 1);
	flow_record.tcp_flags = 7;
	ret = check_filter_block("flags SF", &flow_record, 1);
	ret = check_filter_block("flags R", &flow_record, 1);
	ret = check_filter_block("flags P", &flow_record, 0);
	ret = check_filter_block("flags A", &flow_record, 0);
	ret = check_filter_block("flags = 7 ", &flow_record, 1);
	ret = check_filter_block("flags > 7 ", &flow_record, 0);
	ret = check_filter_block("flags > 6 ", &flow_record, 1);
	ret = check_filter_block("flags < 7 ", &flow_record, 0);
	ret = check_filter_block("flags < 8 ", &flow_record, 1);

	flow_record.tos = 5;
	ret = check_filter_block("tos 5", &flow_record, 1);
	ret = check_filter_block("tos = 5", &flow_record, 1);
	ret = check_filter_block("tos > 5", &flow_record, 0);
	ret = check_filter_block("tos < 5", &flow_record, 0);
	ret = check_filter_block("tos > 4", &flow_record, 1);
	ret = check_filter_block("tos < 6", &flow_record, 1);

	ret = check_filter_block("tos 10", &flow_record, 0);

	flow_record.input = 5;
	ret = check_filter_block("in if 5", &flow_record, 1);
	ret = check_filter_block("in if 6", &flow_record, 0);
	ret = check_filter_block("out if 6", &flow_record, 0);
	flow_record.output = 6;
	ret = check_filter_block("out if 6", &flow_record, 1);

	/* 
	 * 172.32.7.17 => 0xac200711
	 */
	flow_record.dPkts = 1000;
	ret = check_filter_block("packets 1000", &flow_record, 1);
	ret = check_filter_block("packets = 1000", &flow_record, 1);
	ret = check_filter_block("packets 1010", &flow_record, 0);
	ret = check_filter_block("packets < 1010", &flow_record, 1);
	ret = check_filter_block("packets > 110", &flow_record, 1);

	flow_record.dOctets = 2000;
	ret = check_filter_block("bytes 2000", &flow_record, 1);
	ret = check_filter_block("bytes  = 2000", &flow_record, 1);
	ret = check_filter_block("bytes 2010", &flow_record, 0);
	ret = check_filter_block("bytes < 2010", &flow_record, 1);
	ret = check_filter_block("bytes > 210", &flow_record, 1);

	flow_record.dOctets = 2048;
	ret = check_filter_block("bytes 2k", &flow_record, 1);
	ret = check_filter_block("bytes < 2k", &flow_record, 0);
	ret = check_filter_block("bytes > 2k", &flow_record, 0);
	flow_record.dOctets *= 1024;
	ret = check_filter_block("bytes 2m", &flow_record, 1);
	ret = check_filter_block("bytes < 2m", &flow_record, 0);
	ret = check_filter_block("bytes > 2m", &flow_record, 0);
	flow_record.dOctets *= 1024;
	ret = check_filter_block("bytes 2g", &flow_record, 1);
	ret = check_filter_block("bytes < 2g", &flow_record, 0);
	ret = check_filter_block("bytes > 2g", &flow_record, 0);

	/* 
	 * Function tests
	 */
	flow_record.first = 1089534600;		/* 2004-07-11 10:30:00 */
	flow_record.last  = 1089534600;		/* 2004-07-11 10:30:00 */
	flow_record.msec_first = 10;
	flow_record.msec_last  = 20;

	/* duration 10ms */
	ret = check_filter_block("duration == 10", &flow_record, 1);
	ret = check_filter_block("duration < 11", &flow_record, 1);
	ret = check_filter_block("duration > 9", &flow_record, 1);
	ret = check_filter_block("not duration == 10", &flow_record, 0);
	ret = check_filter_block("duration > 10", &flow_record, 0);
	ret = check_filter_block("duration < 10", &flow_record, 0);

	flow_record.first = 1089534600;		/* 2004-07-11 10:30:00 */
	flow_record.last  = 1089534610;		/* 2004-07-11 10:30:10 */
	flow_record.msec_first = 0;
	flow_record.msec_last  = 0;

	/* duration 10s */
	flow_record.dPkts = 1000;
	ret = check_filter_block("duration == 10000", &flow_record, 1);
	ret = check_filter_block("duration < 10001", &flow_record, 1);
	ret = check_filter_block("duration > 9999", &flow_record, 1);
	ret = check_filter_block("not duration == 10000", &flow_record, 0);
	ret = check_filter_block("duration > 10000", &flow_record, 0);
	ret = check_filter_block("duration < 10000", &flow_record, 0);

	ret = check_filter_block("pps == 100", &flow_record, 1);
	ret = check_filter_block("pps < 101", &flow_record, 1);
	ret = check_filter_block("pps > 99", &flow_record, 1);
	ret = check_filter_block("not pps == 100", &flow_record, 0);
	ret = check_filter_block("pps > 100", &flow_record, 0);
	ret = check_filter_block("pps < 100", &flow_record, 0);

	flow_record.dOctets = 1000;
	ret = check_filter_block("bps == 800", &flow_record, 1);
	ret = check_filter_block("bps < 801", &flow_record, 1);
	ret = check_filter_block("bps > 799", &flow_record, 1);
	ret = check_filter_block("not bps == 800", &flow_record, 0);
	ret = check_filter_block("bps > 800", &flow_record, 0);
	ret = check_filter_block("bps < 800", &flow_record, 0);

	flow_record.dOctets = 20000;
	ret = check_filter_block("bps > 1k", &flow_record, 1);
	ret = check_filter_block("bps > 15k", &flow_record, 1);
	ret = check_filter_block("bps > 16k", &flow_record, 0);

	ret = check_filter_block("bpp == 20", &flow_record, 1);
	ret = check_filter_block("bpp < 21", &flow_record, 1);
	ret = check_filter_block("bpp > 19", &flow_record, 1);
	ret = check_filter_block("not bpp == 20", &flow_record, 0);
	ret = check_filter_block("bpp > 20", &flow_record, 0);
	ret = check_filter_block("bpp < 20", &flow_record, 0);

	// ident checks
	CurrentIdent = "channel1";
	ret = check_filter_block("ident channel1", &flow_record, 1);
	ret = check_filter_block("ident channel", &flow_record, 0);
	ret = check_filter_block("ident channel11", &flow_record, 0);
	ret = check_filter_block("not ident channel1", &flow_record, 0);
	ret = check_filter_block("ident none", &flow_record, 0);
	ret = check_filter_block("not ident none", &flow_record, 1);

	return 0;
}
