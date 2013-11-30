
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
 *  $Id: nfgen.c 5 2004-11-29 15:50:44Z peter $
 *
 *  $LastChangedRevision: 5 $
 *	
 */

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

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif


#include "netflow_v5.h"
#include "netflow_v7.h"
#include "nf_common.h"

static time_t	when = 1092990600;
time_t offset  = 300;

void SendHeader (int netflow_version, int numrecords) {
netflow_v7_header_t	nf_header;

	nf_header.version 		= netflow_version;
	nf_header.count			= numrecords;
	nf_header.SysUptime		= when;
	nf_header.unix_secs		= 0;
	nf_header.unix_nsecs	= 0;
	nf_header.flow_sequence	= 0;
	nf_header.reserved		= 0;

	write(1, &nf_header, NETFLOW_V5_HEADER_LENGTH);

} // End of SendHeader

void SendRecord(int netflow_version, char *src_ip, char *dst_ip, int src_port, int dst_port, 
	int proto, int tcp_flags, int tos, int packets, int bytes, int src_as, int dst_as) {
netflow_v7_record_t	nf_record;

	nf_record.srcaddr		= ntohl(inet_addr(src_ip));
	nf_record.dstaddr		= ntohl(inet_addr(dst_ip));
	nf_record.nexthop		= 0;
	nf_record.input			= 0;
	nf_record.output		= 255;
	nf_record.dPkts			= packets;
	nf_record.dOctets		= bytes;
	nf_record.First			= when - offset;
	nf_record.Last			= when;
	nf_record.srcport		= src_port;
	nf_record.dstport		= dst_port;
	nf_record.flags			= 0;
	nf_record.tcp_flags		= tcp_flags;
	nf_record.prot			= proto;
	nf_record.tos			= tos;
	nf_record.src_as		= src_as;
	nf_record.dst_as		= dst_as;
	nf_record.src_mask		= 0;
	nf_record.dst_mask		= 0;
	nf_record.pad			= 0;
	nf_record.router_sc		= 0;
	offset += 60;
	when -= 2 * offset;

	write(1, &nf_record, netflow_version == 5 ? NETFLOW_V5_RECORD_LENGTH : NETFLOW_V7_RECORD_LENGTH);

} // End of SendRecord

int main( int argc, char **argv ) {
char c;
int	netflow_version;

	netflow_version = 5;

	while ((c = getopt(argc, argv, "v:")) != EOF) {
		switch(c) {
			case 'v':
				netflow_version = atoi(optarg);
				if ( netflow_version != 5 && netflow_version != 7 ) {
					fprintf(stderr, "ERROR: Supports only netflow version 5 and 7\n");
					exit(255);
				}
				break;
			default:
				fprintf(stderr, "ERROR: Unsupported option: '%c'\n", c);
				exit(255);
		}
	}

	SendHeader(netflow_version, 13);
	SendRecord(netflow_version, "172.16.1.66", "172.16.19.18", 1024,  25,  6,  0,   0, 101,     101, 775, 8404);
	SendRecord(netflow_version, "172.16.1.66", "172.16.19.18", 1024,  25,  6,  0,   0, 101,     101, 775, 8404);
	SendRecord(netflow_version, "172.16.1.66", "172.16.19.18", 1024,  25,  6,  0,   0, 101,     101, 775, 8404);
	SendRecord(netflow_version, "172.16.2.66", "172.16.18.18", 2024,  25, 17,  1,   1, 1001,    1001, 775, 8404);
	SendRecord(netflow_version, "172.16.3.66", "172.16.17.18", 3024,  25, 51,  2,   2, 10001,   10001, 775, 8404);
	SendRecord(netflow_version, "172.16.4.66", "172.16.16.18", 4024,  25,  6,  4,   3, 100001,  100001, 775, 8404);
	SendRecord(netflow_version, "172.16.5.66", "172.16.15.18", 5024,  25,  6,  8,   4, 1000001, 1000001, 775, 8404);
	SendRecord(netflow_version, "172.16.6.66", "172.16.14.18", 6024,  25,  6, 16,   5, 500,     10000001, 775, 8404);
	SendRecord(netflow_version, "172.16.6.66", "172.16.14.18", 6024,  25,  6, 16,   5, 500,     10000001, 775, 8404);
	SendRecord(netflow_version, "172.16.7.66", "172.16.13.18", 7024,  25,  6, 32, 255, 5000,    100000001, 775, 8404);
	SendRecord(netflow_version, "172.16.8.66", "172.16.12.18", 8024,  25,  6, 63,   0, 5000,    1000000001, 775, 8404);
	SendRecord(netflow_version, "172.16.2.66", "172.16.18.18", 0,      8,  1,  0,   0, 50000,   50000, 775, 8404);
	SendRecord(netflow_version, "172.160.160.166", "172.160.160.180", 10024, 25000,  6,  0,   0, 500000,  500000, 775, 8404);
	close(1);
	return 0;
}

