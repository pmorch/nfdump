
/*
 *  nfgen :  Test Programm
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
 *  $Id: nfgen.c 70 2006-05-17 08:38:01Z peter $
 *
 *  $LastChangedRevision: 70 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "nfnet.h"
#include "nf_common.h"
#include "util.h"
#include "launch.h"
#include "netflow_v5_v7.h"

const uint16_t MAGIC   = 0xA50C;
const uint16_t VERSION = 1;

static time_t	when = 1089534600;
uint32_t offset  = 10;
uint32_t msecs   = 10;

uint32_t            byte_limit, packet_limit;
int                 byte_mode, packet_mode, failed;

void *GenRecord(int af, void *writeto, char *src_ip, char *dst_ip, int src_port, int dst_port, 
	int proto, int tcp_flags, int tos, uint64_t packets, uint64_t bytes, int src_as, int dst_as);

void *GenRecord(int af, void *writeto, char *src_ip, char *dst_ip, int src_port, int dst_port, 
	int proto, int tcp_flags, int tos, uint64_t packets, uint64_t bytes, int src_as, int dst_as) {
common_record_t	*nf_record = (common_record_t *)writeto;
void	*val;

	nf_record->flags		= 0;
	nf_record->mark			= 0;
	nf_record->first		= when;
	nf_record->last			= when + offset;
	nf_record->msec_first	= msecs;
	nf_record->msec_last	= msecs + 10;

	nf_record->input		= 0;
	nf_record->output		= 255;
	nf_record->srcport		= src_port;
	nf_record->dstport		= dst_port;
	nf_record->dir			= 0;
	nf_record->tcp_flags	= tcp_flags;
	nf_record->prot			= proto;
	nf_record->tos			= tos;
	nf_record->srcas		= src_as;
	nf_record->dstas		= dst_as;

	if ( af == PF_INET6 ) {
		ipv6_block_t	addr;
		nf_record->flags		= 1;
		inet_pton(PF_INET6, src_ip, &addr.srcaddr );
		inet_pton(PF_INET6, dst_ip, &addr.dstaddr );
		addr.srcaddr[0] = ntohll(addr.srcaddr[0]);
		addr.srcaddr[1] = ntohll(addr.srcaddr[1]);
		addr.dstaddr[0] = ntohll(addr.dstaddr[0]);
		addr.dstaddr[1] = ntohll(addr.dstaddr[1]);
		memcpy((void *)nf_record->data, (void *)&addr, sizeof(ipv6_block_t));
		val = (void *)((pointer_addr_t)nf_record->data + sizeof(ipv6_block_t));
		fprintf(stderr, "IPv6 ");
	} else {
		uint32_t	*v4addr = (uint32_t *)nf_record->data;
		inet_pton(PF_INET, src_ip, &v4addr[0] );
		inet_pton(PF_INET, dst_ip, &v4addr[1] );
		v4addr[0] = ntohl(v4addr[0]);
		v4addr[1] = ntohl(v4addr[1]);
		val = (void *)((pointer_addr_t)nf_record->data + 2 * sizeof(uint32_t));
		fprintf(stderr, "IPv4 ");
	}

	if ( packets > 0xffffffffLL ) {
		/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
		uint32_t	*outbuffer = (uint32_t *)val;
		value64_t	v;
		
		v.val.val64 = packets;
		outbuffer[0] = v.val.val32[0];
		outbuffer[1] = v.val.val32[1];
		val = (void *)&outbuffer[2];
		nf_record->flags |= FLAG_PKG_64;
		fprintf(stderr, "packets 64bit ");
	} else {
		uint32_t *v = (uint32_t *)val;
		*v++ = packets;
		val = (void *)v;
		fprintf(stderr, "packets 32bit ");
	}

	if ( bytes > 0xffffffffLL ) {
		/* 64bit access to potentially unaligned output buffer. use 2 x 32bit for _LP64 CPUs */
		uint32_t	*outbuffer = (uint32_t *)val;
		value64_t	v;
		
		v.val.val64 = bytes;
		outbuffer[0] = v.val.val32[0];
		outbuffer[1] = v.val.val32[1];
		val = (void *)&outbuffer[2];
		nf_record->flags |= FLAG_BYTES_64;
		fprintf(stderr, "bytes 64bit ");
	} else {
		uint32_t *v = (uint32_t *)val;
		*v++ = bytes;
		val = (void *)v;

		fprintf(stderr, "bytes 32bit ");
	}
	fprintf(stderr, "Flags: %x\n", nf_record->flags);

	nf_record->size	= (pointer_addr_t)val - (pointer_addr_t)nf_record;

	offset += 10;
	when  += 10;

	msecs += 100;
	if ( msecs > 1000 )
		msecs = msecs - 1000;

	return (void *)((pointer_addr_t)writeto + nf_record->size);

} // End of Gen_v6_Record


int main( int argc, char **argv ) {
char c;
data_block_header_t	*nf_header;
file_header_t		*file_header;
size_t				len;
void				*writeto, *buffer, *records;
uint32_t			numrecords;

	while ((c = getopt(argc, argv, "h")) != EOF) {
		switch(c) {
			case 'h':
				break;
			default:
				fprintf(stderr, "ERROR: Unsupported option: '%c'\n", c);
				exit(255);
		}
	}

	buffer = malloc(1024*1024);
	nf_header = (data_block_header_t *)buffer;
	nf_header->pad				= 0;
	records = writeto = (void *)((pointer_addr_t)buffer + sizeof(data_block_header_t));
	
	// initialize file header and dummy stat record
	len = sizeof(file_header_t) + sizeof(stat_record_t);
	file_header = (file_header_t *)malloc(len);
	memset((void *)file_header, 0, len);
	file_header->magic 		= MAGIC;
	file_header->version 	= VERSION;
	strncpy(file_header->ident, "none", IDENT_SIZE);
	write(STDOUT_FILENO, (void *)file_header, len) ;

	numrecords = 0;
	//                           src_ip  dst_ip, src_port, dst_port, proto, tcp_flags, tos, packets, bytes, src_as, dst_as
	writeto = GenRecord(PF_INET, writeto, "172.16.1.66", "192.168.170.100", 1024,  25,  6,  0,   0, 101,     101, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET, writeto, "172.16.2.66", "192.168.170.101", 1024,  25,  6,  0,   0, 101,     101, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET, writeto, "172.16.3.66", "192.168.170.102", 1024,  25,  6,  0,   0, 101,     101, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET, writeto, "172.16.4.66", "192.168.170.103", 2024,  25, 17,  1,   1, 1001,    1001, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET, writeto, "172.16.5.66", "192.168.170.104", 3024,  25, 51,  2,   2, 10001,   10001, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET, writeto, "172.16.6.66", "192.168.170.105", 4024,  25,  6,  4,   3, 100001,  100001, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET, writeto, "172.16.7.66", "192.168.170.106", 5024,  25,  6,  8,   4, 1000001, 1000001, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET, writeto, "172.16.8.66", "192.168.170.107", 5024,  25,  6,  1,   4, 10000010, 1001, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET, writeto, "172.16.9.66", "192.168.170.108", 6024,  25,  6, 16,   5, 500,     10000001, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET, writeto, "172.16.10.66", "192.168.170.109", 6024,  25,  6, 16,   5, 500,     10000001, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET, writeto, "172.16.11.66", "192.168.170.110", 7024,  25,  6, 32, 255, 5000,    100000001, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET, writeto, "172.16.12.66", "192.168.170.111", 8024,  25,  6, 63,   0, 5000,    1000000001, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET, writeto, "172.16.13.66", "192.168.170.112", 0,      8,  1,  0,   0, 50000,   50000, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET, writeto, "172.160.160.166", "172.160.160.180", 10024, 25000,  6,  0,   0, 500000,  500000, 775, 8404);
	numrecords++;

	writeto = GenRecord(PF_INET6, writeto, "fe80::2110:abcd:1234:0", "fe80::2110:abcd:1235:4321", 1024,  25,  6,  27,   0, 10,     15100, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET6, writeto, "2001:234:aabb::211:24ff:fe80:d01e", "2001:620::8:203:baff:fe52:38e5", 10240,  52345,  6,  27,   0, 10100,     15000000, 775, 8404);
	numrecords++;

	// flows with 64 bit counters
	writeto = GenRecord(PF_INET6, writeto, "2001:234:aabb::211:24ff:fe80:d01e", "2001:620::8:203:baff:fe52:38e5", 10240,  52345,  6,  27,   0, 10100000,     0x100000000LL, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET6, writeto, "2001:234:aabb::211:24ff:fe80:d01e", "2001:620::8:203:baff:fe52:38e5", 10240,  52345,  6,  27,   0, 0x100000000LL,     15000000, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET6, writeto, "2001:234:aabb::211:24ff:fe80:d01e", "2001:620::8:203:baff:fe52:38e5", 10240,  52345,  6,  27,   0, 0x100000000LL,     0x200000000LL, 775, 8404);
	numrecords++;

	writeto = GenRecord(PF_INET, writeto, "172.16.14.18", "192.168.170.113", 10240,  52345,  6,  27,   0, 10100000,     0x100000000LL, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET, writeto, "172.16.15.18", "192.168.170.114", 10240,  52345,  6,  27,   0, 0x100000000LL,     15000000, 775, 8404);
	numrecords++;
	writeto = GenRecord(PF_INET, writeto, "172.16.16.18", "192.168.170.115", 10240,  52345,  6,  27,   0, 0x100000000LL,     0x200000000LL, 775, 8404);
	numrecords++;
	
	nf_header->NumBlocks	= numrecords;
	nf_header->size			= (pointer_addr_t)writeto - (pointer_addr_t)records;
	nf_header->id 			= DATA_BLOCK_TYPE_1;
	write(1, nf_header, sizeof(data_block_header_t));
	write(1, records, (pointer_addr_t)writeto - (pointer_addr_t)records);

	return 0;
}

