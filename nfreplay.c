/*
 *  nfreplay :  Reads netflow data from files saved by nfcapd
 *  			and sends them to another host.
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
 *  $Id: nfreplay.c 5 2004-11-29 15:50:44Z peter $
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
#include "version.h"
#include "nf_common.h"
#include "nftree.h"
#include "nfdump.h"
#include "util.h"
#include "grammar.h"

#define BuffNumRecords	1024

// all records should be version 5
#define NETFLOW_VERSION 5

/* Externals */
extern int yydebug;

/* Global Variables */
FilterEngine_data_t	*Engine;
int 		byte_mode, packet_mode;
uint32_t	byte_limit, packet_limit;	// needed for linking purpose only

/* Local Variables */
static char const *rcsid 		  = "$Id: nfreplay.c 5 2004-11-29 15:50:44Z peter $";

/* Function Prototypes */
static void usage(char *name);

static int create_send_socket(unsigned int wmem_size);

static void send_data(char *rfile, int socket, char *send_ip, int send_port, char *filter, 
				time_t twin_start, time_t twin_end, uint32_t count, unsigned int delay);


/* Functions */
static void usage(char *name) {
		printf("usage %s [options] [\"filter\"]\n"
					"-h\t\tthis text you see right here\n"
					"-V\t\tPrint version and exit.\n"
					"-i <ip>\t\tTarget IP address default: 127.0.0.1\n"
					"-p <port>\tTarget port default 9995\n"
					"-d <usec>\tDelay in usec between packets. default 10\n"
					"-c <cnt>\tPacket count. default send all packets\n"
					"-b <bsize>\tSend buffer size.\n"
					"-r <input>\tread from file. default: stdin\n"
					"-f <filter>\tfilter syntaxfile\n"
					"-t <time>\ttime window for sendiing packets\n"
					"\t\tyyyy/MM/dd.hh:mm:ss[-yyyy/MM/dd.hh:mm:ss]\n"
					, name);
} /* usage */

static int create_send_socket(unsigned int wmem_size) {
int send_socket;
unsigned int wmem_actual;
socklen_t optlen;

	// create socket
	send_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (send_socket == -1) {
		perror("Opening output socket failed");
		return 0;
	}
  
	// Set socket write buffer. Need to be root!
	if ( wmem_size > 0 ) {
		if ( geteuid() == 0 ) {
			setsockopt(send_socket, SOL_SOCKET, SO_SNDBUF, &wmem_size, sizeof(wmem_size));
	
			// check what was set (e.g. linux 2.4.20 sets twice of what was requested)
			getsockopt(send_socket, SOL_SOCKET, SO_SNDBUF, &wmem_actual, &optlen);
	
			if (wmem_size != wmem_actual) {
				printf("Warning: Socket write buffer size requested: %u set: %u\n",
			 	wmem_size, wmem_actual);
			} 
		} else {
			printf("Warning: Socket buffer size can only be changed by root!\n");
		}
	}


	return send_socket;

} // End of create_send_socket

static void send_data(char *rfile, int socket, char *send_ip, int send_port, char *filter, 
				time_t twin_start, time_t twin_end, uint32_t count, unsigned int delay) {
nf_header_t nf_header;
netflow_v5_record_t *nf_record, *record_buffer, *sendbuff;	
void		*sendptr;
struct sockaddr_in send_to;
int i, rfd, done, ret, *ftrue, sleepcnt;
uint32_t	NumRecords, numflows, cnt, sendcnt;
double		boot_time;	  

	// address descriptor
	send_to.sin_family = AF_INET;
	send_to.sin_port = htons(send_port);
	// if ( inet_aton(send_ip, &(send_to.sin_addr)) == 0 ) {
	if ((send_to.sin_addr.s_addr = inet_addr(send_ip)) == -1) {
		perror("Invalid target IP address ");
		return;
	}

	rfd = GetNextFile(0, twin_start, twin_end);
	if ( rfd < 0 ) {
		if ( errno ) 
			perror("Can't open file for reading");
		return;
	}

	// prepare read and send buffer
	record_buffer = (netflow_v5_record_t *) calloc(BuffNumRecords , NETFLOW_V5_RECORD_LENGTH);
	sendbuff      = (netflow_v5_record_t *) calloc(BuffNumRecords , NETFLOW_V5_RECORD_LENGTH);
	ftrue 		  = (int *) calloc(BuffNumRecords , sizeof(int));
	if ( !record_buffer || !sendbuff || !ftrue ) {
		perror("Memory allocation error");
		close(rfd);
		return;
	}

	sleepcnt = 0;
	numflows = 0;
	done	 = 0;
	while ( !done ) {
		ret = read(rfd, &nf_header, NETFLOW_V5_HEADER_LENGTH);
		if ( ret == 0 ) {
			done = 1;
			break;
		} else if ( ret == -1 ) {
			perror("Error reading data");
			close(rfd);
			return;
		}
		if ( nf_header.version != NETFLOW_VERSION ) {
			fprintf(stdout, "Not a netflow v5 header\n");
			close(rfd);
			return;
		}
		if ( nf_header.count > BuffNumRecords ) {
			fprintf(stderr, "Too many records %u ( > BuffNumRecords )\n", nf_header.count);
			break;
		}

		NumRecords = nf_header.count;

		ret = read(rfd, record_buffer, NumRecords * NETFLOW_V5_RECORD_LENGTH);
		if ( ret == 0 ) {
			done = 1;
			break;
		} else if ( ret == -1 ) {
			perror("Error reading data");
			close(rfd);
			return;
		}

		// cnt is the number of blocks, which survived the filter
		// ftrue is an array of flags of the filter result
		sendcnt = cnt = 0;
		sendptr = (void *)sendbuff;
		nf_record = record_buffer;
		for ( i=0; i < NumRecords && numflows < count; i++ ) {
			// if no filter is given, the result is always true
			ftrue[i] = twin_start ? nf_record->First >= twin_start && nf_record->Last <= twin_end : 1;
			Engine->nfrecord = (uint32_t *)nf_record;

			if ( filter && ftrue[i] ) 
				ftrue[i] = (*Engine->FilterEngine)(Engine);

			if ( ftrue[i] ) {
				cnt++;
				numflows++;
			}
		}

		// set new count in v5 header
		nf_header.count = cnt;

		// dump header and records only, if any block is left
		if ( cnt ) {
			boot_time  = ((double)(nf_header.unix_secs) + 1e-9 * (double)(nf_header.unix_nsecs)) -
							(0.001 * (double)(nf_header.SysUptime));

			nf_header.version 		= htons(nf_header.version);
			nf_header.count 		= htons(nf_header.count);
			nf_header.SysUptime	 	= htonl(nf_header.SysUptime);
			nf_header.unix_secs	 	= htonl(nf_header.unix_secs);
			nf_header.unix_nsecs	= htonl(nf_header.unix_nsecs);
			nf_header.flow_sequence	= htonl(nf_header.flow_sequence);

			/* send to socket */
			ret = sendto(socket, (void *)&nf_header, NETFLOW_V5_HEADER_LENGTH, 0, 
					(struct sockaddr *)&send_to, sizeof(send_to));
			if ( ret < 0 ) {
				perror("Error sending data");
				close(rfd);
				return;
			}

			nf_record = record_buffer;
			for ( i=0; i < NumRecords; i++ ) {
				if ( ftrue[i] ) {
					nf_record->First = (uint32_t)(((double)nf_record->First - boot_time ) * 1000);
					nf_record->Last  = (uint32_t)(((double)nf_record->Last  - boot_time ) * 1000);

					nf_record->srcaddr	= htonl(nf_record->srcaddr);
  					nf_record->dstaddr	= htonl(nf_record->dstaddr);
  					nf_record->nexthop	= htonl(nf_record->nexthop);
  					nf_record->input	= htons(nf_record->input);
  					nf_record->output	= htons(nf_record->output);
  					nf_record->dPkts	= htonl(nf_record->dPkts);
  					nf_record->dOctets	= htonl(nf_record->dOctets);
  					nf_record->First	= htonl(nf_record->First);
  					nf_record->Last		= htonl(nf_record->Last);
  					nf_record->srcport	= htons(nf_record->srcport);
  					nf_record->dstport	= htons(nf_record->dstport);
  					nf_record->src_as	= htons(nf_record->src_as);
  					nf_record->dst_as	= htons(nf_record->dst_as);

					memcpy(sendptr, nf_record, NETFLOW_V5_RECORD_LENGTH);
					sendptr = (void *)((pointer_addr_t)sendptr + NETFLOW_V5_RECORD_LENGTH);
					sendcnt++;
				}
				// increment pointer by number of bytes for netflow record
				nf_record = (void *)((pointer_addr_t)nf_record + NETFLOW_V5_RECORD_LENGTH);

			}

			ret = sendto(socket, (void *)sendbuff, sendcnt * NETFLOW_V5_RECORD_LENGTH, 0, 
				(struct sockaddr *)&send_to, sizeof(send_to));

			if ( ret < 0 ) {
				perror("Error writing data");
				close(rfd);
				return;
			}

			if ( delay )
				if ( sleepcnt++ == 10 ) {
					// sleep as specified
					usleep(delay);
					sleepcnt = 0;
				}

		} // if cnt 
	} // while

} // End of send_data


int main( int argc, char **argv ) {
struct stat stat_buff;
char c, *rfile, *ffile, *filter, *tstring;
char *send_ip;
int send_port, ffd, ret, sockfd;
unsigned int delay, count, sockbuff;
time_t t_start, t_end;

	rfile = ffile = filter = tstring = NULL;
	t_start = t_end = 0;
	send_ip   		= "127.0.0.1";
	send_port 		= 9995;
	delay 	  		= 10;
	count	  		= 0xFFFFFFFF;
	sockbuff  		= 0;
	while ((c = getopt(argc, argv, "hi:p:d:c:b:r:f:t:V")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'V':
				printf("%s: Version: %s %s\n%s\n",argv[0], nfdump_version, nfdump_date, rcsid);
				exit(0);
				break;
			case 'i':
				send_ip = optarg;
				break;
			case 'p':
				send_port = atoi(optarg);
				if ( send_port <= 0 || send_port > 65535 ) {
					fprintf(stderr, "Send port out of range\n");
					exit(255);
				}
				break;
			case 'd':
				delay = atoi(optarg);
				break;
			case 'c':
				count = atoi(optarg);
				break;
			case 'b':
				sockbuff = atoi(optarg);
				break;
			case 'f':
				ffile = optarg;
				break;
			case 't':
				tstring = optarg;
				break;
			case 'r':
				rfile = optarg;
				break;
			default:
				usage(argv[0]);
				exit(0);
		}
	}
	if (argc - optind > 1) {
		usage(argv[0]);
		exit(255);
	} else {
		/* user specified a pcap filter */
		filter = argv[optind];
	}

	if ( !filter && ffile ) {
		if ( stat(ffile, &stat_buff) ) {
			perror("Can't stat file");
			exit(255);
		}
		filter = (char *)malloc(stat_buff.st_size);
		if ( !filter ) {
			perror("Memory error");
			exit(255);
		}
		ffd = open(ffile, O_RDONLY);
		if ( ffd < 0 ) {
			perror("Can't open file");
			exit(255);
		}
		ret = read(ffd, (void *)filter, stat_buff.st_size);
		if ( ret < 0   ) {
			perror("Error reading file");
			close(ffd);
			exit(255);
		}
		close(ffd);
	}

	if ( !filter )
		filter = "any";

	Engine = CompileFilter(filter);
	if ( !Engine ) 
		exit(254);
	
	sockfd = create_send_socket(sockbuff);
	if ( sockfd <= 0 ) {
		exit(255);
	}


	SetupInputFileSequence(NULL,rfile, NULL);

	if ( tstring ) {
		if ( !ScanTimeFrame(tstring, &t_start, &t_end) )
			exit(255);
	}

	send_data(rfile, sockfd, send_ip, send_port, filter, t_start, t_end, count, delay);

	return 0;
}
