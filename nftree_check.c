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
 *  $Id: nftree_check.c 2 2004-09-20 18:12:36Z peter $
 *
 *  $LastChangedRevision: 2 $
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
#include "netflow_v5.h"
#include "nf_common.h"

/* Global Variables */
FilterEngine_data_t	*Engine;
uint32_t			byte_limit, packet_limit;
int 				byte_mode, packet_mode, failed;

#define TCP	6
#define UDP 17

int check(char *filter, struct netflow_v5_record *v5record, int expect);

int check(char *filter, struct netflow_v5_record *v5record, int expect) {
int ret;

	Engine = CompileFilter(filter);
	if ( !Engine ) {
		exit(254);
	}

	Engine->nfrecord = (uint32_t *)v5record;
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
struct netflow_v5_record v5record;
uint32_t *blocks;
time_t	now;
int ret;

	failed = 0;
	memset((void *)&v5record, 0, NETFLOW_V5_RECORD_LENGTH);
	blocks = (uint32_t *)&v5record;
	
	printf("Src AS   Offset: %i\n", (pointer_addr_t)&v5record.src_as  - (pointer_addr_t)&blocks[10]);
	printf("Dst AS   Offset: %i\n", (pointer_addr_t)&v5record.dst_as  - (pointer_addr_t)&blocks[10]);
	printf("Src Port Offset: %i\n", (pointer_addr_t)&v5record.srcport - (pointer_addr_t)&blocks[8]);
	printf("Dst Port Offset: %i\n", (pointer_addr_t)&v5record.dstport - (pointer_addr_t)&blocks[8]);
	printf("Protocol Offset: %i\n", (pointer_addr_t)&v5record.prot    - (pointer_addr_t)&blocks[9]);

	printf("Pointer Size : %i\n", sizeof(blocks));
	printf("Time_t Size  : %i\n", sizeof(now));

	v5record.prot	 = TCP;
	ret = check("any", &v5record, 1);
	ret = check("tcp", &v5record, 1);
	ret = check("udp", &v5record, 0);
	v5record.prot = UDP;
	ret = check("tcp", &v5record, 0);
	ret = check("udp", &v5record, 1);
	v5record.prot = 41;
	ret = check("proto 41", &v5record, 1);
	ret = check("proto 42", &v5record, 0);

	/* 172.32.7.16 => 0xac200710
	 * 10.10.10.11 => 0x0a0a0a0b
	 */
	v5record.srcaddr = 0xac200710;
	v5record.dstaddr = 0x0a0a0a0b;
	ret = check("src ip 172.32.7.16", &v5record, 1);
	ret = check("src ip 172.32.7.15", &v5record, 0);
	ret = check("dst ip 10.10.10.11", &v5record, 1);
	ret = check("dst ip 10.10.10.10", &v5record, 0);
	ret = check("ip 172.32.7.16", &v5record, 1);
	ret = check("ip 10.10.10.11", &v5record, 1);
	ret = check("ip 172.32.7.17", &v5record, 0);
	ret = check("ip 10.10.10.12", &v5record, 0);
	ret = check("not ip 172.32.7.16", &v5record, 0);
	ret = check("not ip 172.32.7.17", &v5record, 1);

	ret = check("src host 172.32.7.16", &v5record, 1);
	ret = check("src host 172.32.7.15", &v5record, 0);
	ret = check("dst host 10.10.10.11", &v5record, 1);
	ret = check("dst host 10.10.10.10", &v5record, 0);
	ret = check("host 172.32.7.16", &v5record, 1);
	ret = check("host 10.10.10.11", &v5record, 1);
	ret = check("host 172.32.7.17", &v5record, 0);
	ret = check("host 10.10.10.12", &v5record, 0);
	ret = check("not host 172.32.7.16", &v5record, 0);
	ret = check("not host 172.32.7.17", &v5record, 1);

	v5record.srcport = 63;
	v5record.dstport = 255;
	ret = check("src port 63", &v5record, 1);
	ret = check("dst port 255", &v5record, 1);
	ret = check("port 63", &v5record, 1);
	ret = check("port 255", &v5record, 1);
	ret = check("src port 64", &v5record, 0);
	ret = check("dst port 258", &v5record, 0);
	ret = check("port 64", &v5record, 0);
	ret = check("port 258", &v5record, 0);

	ret = check("src port = 63", &v5record, 1);
	ret = check("src port == 63", &v5record, 1);
	ret = check("src port eq 63", &v5record, 1);
	ret = check("src port > 62", &v5record, 1);
	ret = check("src port gt 62", &v5record, 1);
	ret = check("src port > 63", &v5record, 0);
	ret = check("src port < 64", &v5record, 1);
	ret = check("src port lt 64", &v5record, 1);
	ret = check("src port < 63", &v5record, 0);

	ret = check("dst port = 255", &v5record, 1);
	ret = check("dst port == 255", &v5record, 1);
	ret = check("dst port eq 255", &v5record, 1);
	ret = check("dst port > 254", &v5record, 1);
	ret = check("dst port gt 254", &v5record, 1);
	ret = check("dst port > 255", &v5record, 0);
	ret = check("dst port < 256", &v5record, 1);
	ret = check("dst port lt 256", &v5record, 1);
	ret = check("dst port < 255", &v5record, 0);

	v5record.src_as = 123;
	v5record.dst_as = 456;
	ret = check("src as 123", &v5record, 1);
	ret = check("dst as 456", &v5record, 1);
	ret = check("as 123", &v5record, 1);
	ret = check("as 456", &v5record, 1);
	ret = check("src as 124", &v5record, 0);
	ret = check("dst as 457", &v5record, 0);
	ret = check("as 124", &v5record, 0);
	ret = check("as 457", &v5record, 0);

	ret = check("src net 172.32/16", &v5record, 1);
	ret = check("src net 172.32.7/24", &v5record, 1);
	ret = check("src net 172.32.7/27", &v5record, 1);
	ret = check("src net 172.32.7/28", &v5record, 0);
	ret = check("src net 172.32.7.0 255.255.255.0", &v5record, 1);
	ret = check("src net 172.32.7.0 255.255.255.240", &v5record, 0);

	ret = check("dst net 10.10/16", &v5record, 1);
	ret = check("dst net 10.10.10/24", &v5record, 1);
	ret = check("dst net 10.10.10/28", &v5record, 1);
	ret = check("dst net 10.10.10/29", &v5record, 0);
	ret = check("dst net 10.10.10.0 255.255.255.240", &v5record, 1);
	ret = check("dst net 10.10.10.0 255.255.255.248", &v5record, 0);

	ret = check("net 172.32/16", &v5record, 1);
	ret = check("net 172.32.7/24", &v5record, 1);
	ret = check("net 172.32.7/27", &v5record, 1);
	ret = check("net 172.32.7/28", &v5record, 0);
	ret = check("net 172.32.7.0 255.255.255.0", &v5record, 1);
	ret = check("net 172.32.7.0 255.255.255.240", &v5record, 0);

	ret = check("net 10.10/16", &v5record, 1);
	ret = check("net 10.10.10/24", &v5record, 1);
	ret = check("net 10.10.10/28", &v5record, 1);
	ret = check("net 10.10.10/29", &v5record, 0);
	ret = check("net 10.10.10.0 255.255.255.240", &v5record, 1);
	ret = check("net 10.10.10.0 255.255.255.240", &v5record, 1);
	ret = check("net 10.10.10.0 255.255.255.248", &v5record, 0);

	ret = check("src ip 172.32.7.16 or src ip 172.32.7.15", &v5record, 1);
	ret = check("src ip 172.32.7.15 or src ip 172.32.7.16", &v5record, 1);
	ret = check("src ip 172.32.7.15 or src ip 172.32.7.14", &v5record, 0);
	ret = check("src ip 172.32.7.16 and dst ip 10.10.10.11", &v5record, 1);
	ret = check("src ip 172.32.7.15 and dst ip 10.10.10.11", &v5record, 0);
	ret = check("src ip 172.32.7.16 and dst ip 10.10.10.12", &v5record, 0);

	return failed;
}
