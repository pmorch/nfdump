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
 *  $Id: nftree_check.c 51 2005-08-26 10:58:13Z peter $
 *
 *  $LastChangedRevision: 51 $
 *	
 */

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nfdump.h"
#include "nftree.h"
#include "nf_common.h"

/* Global Variables */
FilterEngine_data_t	*Engine;
uint32_t			byte_limit, packet_limit;
int 				byte_mode, packet_mode, failed;

#define TCP	6
#define UDP 17

int check(char *filter, struct flow_record *flow_record, int expect);

int check(char *filter, struct flow_record *flow_record, int expect) {
int ret;

	Engine = CompileFilter(filter);
	if ( !Engine ) {
		exit(254);
	}

	Engine->nfrecord = (uint32_t *)flow_record;
	ret =  (*Engine->FilterEngine)(Engine);
	if ( ret == expect ) {
		printf("Success: Startnode: %i Numblocks: %i Extended: %i Filter: '%s'\n", Engine->StartNode, nblocks(), Engine->Extended, filter);
	} else {
		printf("**** FAILED **** Startnode: %i Numblocks: %i Extended: %i Filter: '%s'\n", Engine->StartNode, nblocks(), Engine->Extended, filter);
		DumpList(Engine);
		printf("Expected: %i, Found: %i\n", expect, ret);
		failed = 1;
	}
	return (ret == expect);
}

int main(int argc, char **argv) {
struct flow_record flow_record;
uint32_t *blocks;
time_t	now;
int ret;

	failed = 0;
	memset((void *)&flow_record, 0, FLOW_RECORD_LENGTH);
	blocks = (uint32_t *)&flow_record;
	
	printf("Src AS   Offset: %u\n", (unsigned int)((pointer_addr_t)&flow_record.src_as  - (pointer_addr_t)&blocks[10]));
	printf("Dst AS   Offset: %u\n", (unsigned int)((pointer_addr_t)&flow_record.dst_as  - (pointer_addr_t)&blocks[10]));
	printf("Src Port Offset: %u\n", (unsigned int)((pointer_addr_t)&flow_record.srcport - (pointer_addr_t)&blocks[8]));
	printf("Dst Port Offset: %u\n", (unsigned int)((pointer_addr_t)&flow_record.dstport - (pointer_addr_t)&blocks[8]));
	printf("Protocol Offset: %u\n", (unsigned int)((pointer_addr_t)&flow_record.prot    - (pointer_addr_t)&blocks[9]));

#if defined __OpenBSD__ || defined __FreeBSD__
	printf("Pointer Size : %u\n", sizeof(blocks));
	printf("Time_t  Size : %u\n", sizeof(now));
	printf("int     Size : %u\n", sizeof(int));
	printf("long    Size : %u\n", sizeof(long));
	if ( FLOW_HEADER_LENGTH != 24 ) {
		printf("**** FAILED **** Header length reported %u, expected 24\n", FLOW_HEADER_LENGTH);
	}  
	if ( FLOW_RECORD_LENGTH != 48 ) {
		printf("**** FAILED **** Record length reported %u, expected 48\n", FLOW_RECORD_LENGTH);
	}  
#else
	printf("Pointer Size : %u\n", sizeof(blocks));
	printf("Time_t  Size : %u\n", sizeof(now));
	printf("int     Size : %u\n", sizeof(int));
	printf("long    Size : %u\n", sizeof(long));
	if ( FLOW_HEADER_LENGTH != 24 ) {
		printf("**** FAILED **** Header length reported %u, expected 24\n", FLOW_HEADER_LENGTH);
	}  
	if ( FLOW_RECORD_LENGTH != 48 ) {
		printf("**** FAILED **** Record length reported %u, expected 48\n", FLOW_RECORD_LENGTH);
	}  
#endif

	flow_record.prot	 = TCP;
	ret = check("any", &flow_record, 1);
	ret = check("not any", &flow_record, 0);
	ret = check("tcp", &flow_record, 1);
	ret = check("udp", &flow_record, 0);
	flow_record.prot = UDP;
	ret = check("tcp", &flow_record, 0);
	ret = check("udp", &flow_record, 1);
	flow_record.prot = 50;
	ret = check("esp", &flow_record, 1);
	ret = check("ah", &flow_record, 0);
	flow_record.prot = 51;
	ret = check("ah", &flow_record, 1);
	flow_record.prot = 46;
	ret = check("rsvp", &flow_record, 1);
	flow_record.prot = 47;
	ret = check("gre", &flow_record, 1);
	ret = check("proto 47", &flow_record, 1);
	ret = check("proto 42", &flow_record, 0);

	/* 172.32.7.16 => 0xac200710
	 * 10.10.10.11 => 0x0a0a0a0b
	 */
	flow_record.srcaddr = 0xac200710;
	flow_record.dstaddr = 0x0a0a0a0b;
	ret = check("src ip 172.32.7.16", &flow_record, 1);
	ret = check("src ip 172.32.7.15", &flow_record, 0);
	ret = check("dst ip 10.10.10.11", &flow_record, 1);
	ret = check("dst ip 10.10.10.10", &flow_record, 0);
	ret = check("ip 172.32.7.16", &flow_record, 1);
	ret = check("ip 10.10.10.11", &flow_record, 1);
	ret = check("ip 172.32.7.17", &flow_record, 0);
	ret = check("ip 10.10.10.12", &flow_record, 0);
	ret = check("not ip 172.32.7.16", &flow_record, 0);
	ret = check("not ip 172.32.7.17", &flow_record, 1);

	ret = check("src host 172.32.7.16", &flow_record, 1);
	ret = check("src host 172.32.7.15", &flow_record, 0);
	ret = check("dst host 10.10.10.11", &flow_record, 1);
	ret = check("dst host 10.10.10.10", &flow_record, 0);
	ret = check("host 172.32.7.16", &flow_record, 1);
	ret = check("host 10.10.10.11", &flow_record, 1);
	ret = check("host 172.32.7.17", &flow_record, 0);
	ret = check("host 10.10.10.12", &flow_record, 0);
	ret = check("not host 172.32.7.16", &flow_record, 0);
	ret = check("not host 172.32.7.17", &flow_record, 1);

	flow_record.srcport = 63;
	flow_record.dstport = 255;
	ret = check("src port 63", &flow_record, 1);
	ret = check("dst port 255", &flow_record, 1);
	ret = check("port 63", &flow_record, 1);
	ret = check("port 255", &flow_record, 1);
	ret = check("src port 64", &flow_record, 0);
	ret = check("dst port 258", &flow_record, 0);
	ret = check("port 64", &flow_record, 0);
	ret = check("port 258", &flow_record, 0);

	ret = check("src port = 63", &flow_record, 1);
	ret = check("src port == 63", &flow_record, 1);
	ret = check("src port eq 63", &flow_record, 1);
	ret = check("src port > 62", &flow_record, 1);
	ret = check("src port gt 62", &flow_record, 1);
	ret = check("src port > 63", &flow_record, 0);
	ret = check("src port < 64", &flow_record, 1);
	ret = check("src port lt 64", &flow_record, 1);
	ret = check("src port < 63", &flow_record, 0);

	ret = check("dst port = 255", &flow_record, 1);
	ret = check("dst port == 255", &flow_record, 1);
	ret = check("dst port eq 255", &flow_record, 1);
	ret = check("dst port > 254", &flow_record, 1);
	ret = check("dst port gt 254", &flow_record, 1);
	ret = check("dst port > 255", &flow_record, 0);
	ret = check("dst port < 256", &flow_record, 1);
	ret = check("dst port lt 256", &flow_record, 1);
	ret = check("dst port < 255", &flow_record, 0);

	flow_record.src_as = 123;
	flow_record.dst_as = 456;
	ret = check("src as 123", &flow_record, 1);
	ret = check("dst as 456", &flow_record, 1);
	ret = check("as 123", &flow_record, 1);
	ret = check("as 456", &flow_record, 1);
	ret = check("src as 124", &flow_record, 0);
	ret = check("dst as 457", &flow_record, 0);
	ret = check("as 124", &flow_record, 0);
	ret = check("as 457", &flow_record, 0);

	ret = check("src net 172.32/16", &flow_record, 1);
	ret = check("src net 172.32.7/24", &flow_record, 1);
	ret = check("src net 172.32.7/27", &flow_record, 1);
	ret = check("src net 172.32.7/28", &flow_record, 0);
	ret = check("src net 172.32.7.0 255.255.255.0", &flow_record, 1);
	ret = check("src net 172.32.7.0 255.255.255.240", &flow_record, 0);

	ret = check("dst net 10.10/16", &flow_record, 1);
	ret = check("dst net 10.10.10/24", &flow_record, 1);
	ret = check("dst net 10.10.10/28", &flow_record, 1);
	ret = check("dst net 10.10.10/29", &flow_record, 0);
	ret = check("dst net 10.10.10.0 255.255.255.240", &flow_record, 1);
	ret = check("dst net 10.10.10.0 255.255.255.248", &flow_record, 0);

	ret = check("net 172.32/16", &flow_record, 1);
	ret = check("net 172.32.7/24", &flow_record, 1);
	ret = check("net 172.32.7/27", &flow_record, 1);
	ret = check("net 172.32.7/28", &flow_record, 0);
	ret = check("net 172.32.7.0 255.255.255.0", &flow_record, 1);
	ret = check("net 172.32.7.0 255.255.255.240", &flow_record, 0);

	ret = check("net 10.10/16", &flow_record, 1);
	ret = check("net 10.10.10/24", &flow_record, 1);
	ret = check("net 10.10.10/28", &flow_record, 1);
	ret = check("net 10.10.10/29", &flow_record, 0);
	ret = check("net 10.10.10.0 255.255.255.240", &flow_record, 1);
	ret = check("net 10.10.10.0 255.255.255.240", &flow_record, 1);
	ret = check("net 10.10.10.0 255.255.255.248", &flow_record, 0);

	ret = check("src ip 172.32.7.16 or src ip 172.32.7.15", &flow_record, 1);
	ret = check("src ip 172.32.7.15 or src ip 172.32.7.16", &flow_record, 1);
	ret = check("src ip 172.32.7.15 or src ip 172.32.7.14", &flow_record, 0);
	ret = check("src ip 172.32.7.16 and dst ip 10.10.10.11", &flow_record, 1);
	ret = check("src ip 172.32.7.15 and dst ip 10.10.10.11", &flow_record, 0);
	ret = check("src ip 172.32.7.16 and dst ip 10.10.10.12", &flow_record, 0);

	flow_record.tcp_flags = 1;
	ret = check("flags F", &flow_record, 1);
	ret = check("flags S", &flow_record, 0);
	ret = check("flags R", &flow_record, 0);
	ret = check("flags P", &flow_record, 0);
	ret = check("flags A", &flow_record, 0);
	ret = check("flags U", &flow_record, 0);
	ret = check("flags X", &flow_record, 0);

	flow_record.tcp_flags = 2;
	ret = check("flags S", &flow_record, 1);
	flow_record.tcp_flags = 4;
	ret = check("flags R", &flow_record, 1);
	flow_record.tcp_flags = 8;
	ret = check("flags P", &flow_record, 1);
	flow_record.tcp_flags = 16;
	ret = check("flags A", &flow_record, 1);
	flow_record.tcp_flags = 32;
	ret = check("flags U", &flow_record, 1);
	flow_record.tcp_flags = 63;
	ret = check("flags X", &flow_record, 1);

	flow_record.tcp_flags = 3;
	ret = check("flags SF", &flow_record, 1);
	ret = check("flags 3", &flow_record, 1);
	flow_record.tcp_flags = 7;
	ret = check("flags SF", &flow_record, 1);
	ret = check("flags R", &flow_record, 1);
	ret = check("flags P", &flow_record, 0);
	ret = check("flags A", &flow_record, 0);
	ret = check("flags = 7 ", &flow_record, 1);
	ret = check("flags > 7 ", &flow_record, 0);
	ret = check("flags > 6 ", &flow_record, 1);
	ret = check("flags < 7 ", &flow_record, 0);
	ret = check("flags < 8 ", &flow_record, 1);

	flow_record.tos = 5;
	ret = check("tos 5", &flow_record, 1);
	ret = check("tos = 5", &flow_record, 1);
	ret = check("tos > 5", &flow_record, 0);
	ret = check("tos < 5", &flow_record, 0);
	ret = check("tos > 4", &flow_record, 1);
	ret = check("tos < 6", &flow_record, 1);

	ret = check("tos 10", &flow_record, 0);

	flow_record.input = 5;
	ret = check("in if 5", &flow_record, 1);
	ret = check("in if 6", &flow_record, 0);
	ret = check("out if 6", &flow_record, 0);
	flow_record.output = 6;
	ret = check("out if 6", &flow_record, 1);

	/* 
	 * 172.32.7.17 => 0xac200711
	 */
	flow_record.nexthop = 0xac200711;
	ret = check("next 172.32.7.17", &flow_record, 1);
	ret = check("next 172.32.7.16", &flow_record, 0);

	flow_record.dPkts = 1000;
	ret = check("packets 1000", &flow_record, 1);
	ret = check("packets = 1000", &flow_record, 1);
	ret = check("packets 1010", &flow_record, 0);
	ret = check("packets < 1010", &flow_record, 1);
	ret = check("packets > 110", &flow_record, 1);

	flow_record.dOctets = 2000;
	ret = check("bytes 2000", &flow_record, 1);
	ret = check("bytes  = 2000", &flow_record, 1);
	ret = check("bytes 2010", &flow_record, 0);
	ret = check("bytes < 2010", &flow_record, 1);
	ret = check("bytes > 210", &flow_record, 1);

	flow_record.dOctets = 2048;
	ret = check("bytes 2k", &flow_record, 1);
	ret = check("bytes < 2k", &flow_record, 0);
	ret = check("bytes > 2k", &flow_record, 0);
	flow_record.dOctets *= 1024;
	ret = check("bytes 2m", &flow_record, 1);
	ret = check("bytes < 2m", &flow_record, 0);
	ret = check("bytes > 2m", &flow_record, 0);
	flow_record.dOctets *= 1024;
	ret = check("bytes 2g", &flow_record, 1);
	ret = check("bytes < 2g", &flow_record, 0);
	ret = check("bytes > 2g", &flow_record, 0);

	/* 
	 * Function tests
	 */
	flow_record.First = 1089534600;		/* 2004-07-11 10:30:00 */
	flow_record.Last  = 1089534600;		/* 2004-07-11 10:30:01 */
	flow_record.msec_first = 10;
	flow_record.msec_last  = 20;

	/* duration 10ms */
	ret = check("duration == 10", &flow_record, 1);
	ret = check("duration < 11", &flow_record, 1);
	ret = check("duration > 9", &flow_record, 1);
	ret = check("not duration == 10", &flow_record, 0);
	ret = check("duration > 10", &flow_record, 0);
	ret = check("duration < 10", &flow_record, 0);

	flow_record.First = 1089534600;		/* 2004-07-11 10:30:00 */
	flow_record.Last  = 1089534610;		/* 2004-07-11 10:30:01 */
	flow_record.msec_first = 0;
	flow_record.msec_last  = 0;

	/* duration 10s */
	flow_record.dPkts = 1000;
	ret = check("duration == 10000", &flow_record, 1);
	ret = check("duration < 10001", &flow_record, 1);
	ret = check("duration > 9999", &flow_record, 1);
	ret = check("not duration == 10000", &flow_record, 0);
	ret = check("duration > 10000", &flow_record, 0);
	ret = check("duration < 10000", &flow_record, 0);

	ret = check("pps == 100", &flow_record, 1);
	ret = check("pps < 101", &flow_record, 1);
	ret = check("pps > 99", &flow_record, 1);
	ret = check("not pps == 100", &flow_record, 0);
	ret = check("pps > 100", &flow_record, 0);
	ret = check("pps < 100", &flow_record, 0);

	flow_record.dOctets = 1000;
	ret = check("bps == 800", &flow_record, 1);
	ret = check("bps < 801", &flow_record, 1);
	ret = check("bps > 799", &flow_record, 1);
	ret = check("not bps == 800", &flow_record, 0);
	ret = check("bps > 800", &flow_record, 0);
	ret = check("bps < 800", &flow_record, 0);

	flow_record.dOctets = 20000;
	ret = check("bps > 1k", &flow_record, 1);
	ret = check("bps > 15k", &flow_record, 1);
	ret = check("bps > 16k", &flow_record, 0);

	ret = check("bpp == 20", &flow_record, 1);
	ret = check("bpp < 21", &flow_record, 1);
	ret = check("bpp > 19", &flow_record, 1);
	ret = check("not bpp == 20", &flow_record, 0);
	ret = check("bpp > 20", &flow_record, 0);
	ret = check("bpp < 20", &flow_record, 0);

	return failed;
}
