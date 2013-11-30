/*
 *  nfdump : Reads netflow data from files, saved by nfcapd
 *  		 Data can be view, filtered and saved to 
 *  		 files.
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
 *  $Id: nfdump.c 53 2005-11-17 07:45:34Z peter $
 *
 *  $LastChangedRevision: 53 $
 *	
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif


#include "netflow_v5.h"
#include "nf_common.h"
#include "nftree.h"
#include "nfprof.h"
#include "nfdump.h"
#include "nfstat.h"
#include "version.h"
#include "util.h"
#include "panonymizer.h"

/* hash parameters */
#define HashBits 20
#define NumPrealloc 128000


/* Global Variables */
FilterEngine_data_t	*Engine;
uint32_t			byte_limit, packet_limit;
int 				byte_mode, packet_mode;

/* Local Variables */
static char const *rcsid 		  = "$Id: nfdump.c 53 2005-11-17 07:45:34Z peter $";
static uint64_t total_bytes;
static uint32_t total_flows;

// Header Legends
#define HEADER_LINE "Date flow start         Duration Proto    Src IP Addr:Port         Dst IP Addr:Port   Packets    Bytes Flows"
//                   2004-07-11 10:31:50.110  120.010 TCP      172.16.8.66:8024  ->    172.16.12.18:25        5000  953.7 M     1


#define HEADER_LINE_LONG "Date flow start         Duration Proto    Src IP Addr:Port         Dst IP Addr:Port   Flags Tos  Packets    Bytes Flows"
//                        2004-07-11 10:31:50.110  120.010 TCP      172.16.8.66:8024  ->    172.16.12.18:25    UAPRSF   0     5000  953.7 M     1


#define HEADER_LINE_EXTENDED "Date flow start         Duration Proto    Src IP Addr:Port         Dst IP Addr:Port   Flags Tos  Packets    Bytes      pps      bps    Bpp Flows"
//                            2004-07-11 10:31:50.110  120.010 TCP      172.16.8.66:8024  ->    172.16.12.18:25    UAPRSF   0     5000  953.7 M       41  1041579 200000     1


// Assign print functions for all output options -o
// Teminated with a NULL record
struct printmap_s {
	char		*printmode;		// name of mode
	int			sorted;			// does it make sense to sort the output in this mode?
	printer_t	func;			// name of the function, which prints the record
	char		*HeaderLine;	// Header line for each output format, if needed. NULL otherwise
} printmap[] = {
	{ "raw",		0, flow_record_raw,     	   		NULL },
	{ "line", 		1, flow_record_to_line,      		HEADER_LINE },
	{ "long", 		1, flow_record_to_line_long, 		HEADER_LINE_LONG },
	{ "extended",	1, flow_record_to_line_extended, 	HEADER_LINE_EXTENDED },
	{ "pipe", 		0, flow_record_to_pipe,      		NULL },
	{ NULL,			0, NULL,                           	NULL }
};

#define DefaultMode "line"

// compare at most 16 chars
#define MAXMODELEN	16	

// all records should be version 5
#define FLOW_VERSION 5

/* Function Prototypes */
static void usage(char *name);

static int ParseAggregateMask( char *arg, uint32_t *AggregateMasks );

static int ParseCryptoPAnKey ( char *s, char *key );

static uint32_t process_data(char *wfile, int element_stat, int flow_stat, int sort_flows,
	printer_t print_header, printer_t print_record, time_t twin_start, time_t twin_end, 
	uint64_t limitflows, uint32_t *AggregateMasks, int anon);

/* Functions */
static void usage(char *name) {
		printf("usage %s [options] [\"filter\"]\n"
					"-h\t\tthis text you see right here\n"
					"-V\t\tPrint version and exit.\n"
					"-a\t\tAggregate netflow data.\n"
					"-A <expr>\tWhat to aggregate: ',' sep list of 'srcip dstip srcport dstport'\n"
					"-r\t\tread input from file\n"
					"-w\t\twrite output to file\n"
					"-f\t\tread netflow filter from file\n"
					"-n\t\tDefine number of top N. \n"
					"-c\t\tLimit number of records to display\n"
					"-S\t\tGenerate netflow statistics info.\n"
					"-s\t\tGenerate SRC IP statistics.\n"
					"-s <expr>\tGenerate statistics for <expr>: srcip, dstip, ip.\n"
					"-l <expr>\tSet limit on packets for line and packed output format.\n"
					"-K <key>\tAnonymize IP addressses using CryptoPAn with key <key>.\n"
					"\t\tkey: 32 character string or 64 digit hex string starting with 0x.\n"
					"-L <expr>\tSet limit on bytes for line and packed output format.\n"
					"-M <expr>\tRead input from multiple directories.\n"
					"\t\t/dir/dir1:dir2:dir3 Read the same files from '/dir/dir1' '/dir/dir2' and '/dir/dir3'.\n"
					"\t\treqquests either -r filename or -R firstfile:lastfile without pathnames\n"
					"-m\t\tPrint netflow data date sorted. Only useful with -M\n"
					"-R <expr>\tRead input from sequence of files.\n"
					"\t\t/any/dir  Read all files in that directory.\n"
					"\t\t/dir/file Read all files beginning with 'file'.\n"
					"\t\t/dir/file1:file2: Read all files from 'file1' to file2.\n"
					"-o <mode>\tUse <mode> to print out netflow records:\n"
					"\t\t raw      Raw record dump.\n"
					"\t\t line     Standard output line format.\n"
					"\t\t long     Standard output line format with additional fields.\n"
					"\t\t extended Even more information.\n"
					"\t\t pipe     '|' separated, machine parseable output format.\n"
					"-X\t\tDump Filtertable and exit (debug option).\n"
					"-Z\t\tCheck filter syntax and exit.\n"
					"-t <time>\ttime window for filtering packets\n"
					"\t\tyyyy/MM/dd.hh:mm:ss[-yyyy/MM/dd.hh:mm:ss]\n", name);
} /* usage */

static int ParseAggregateMask( char *arg, uint32_t *AggregateMasks ) {
char *p;

	p = strtok(arg, ",");
	while ( p ) {
		if (  strcasecmp(p, "srcip" ) == 0 ) {
			AggregateMasks[0] = 0xffffffff;
		} else if ( strcasecmp(p, "dstip" ) == 0 ) {
			AggregateMasks[1] = 0xffffffff;
		} else if ( strcasecmp(p, "srcport" ) == 0 ) {
			AggregateMasks[2] = 0xffffffff;
		} else if ( strcasecmp(p, "dstport" ) == 0 ) {
			AggregateMasks[3] = 0xffffffff;
		} else {
			fprintf(stderr, "Unknown aggregate field: '%s'\n", p);
			return 0;
		}
		p = strtok(NULL, ",");
	}
	return 1;
} /* End of ParseAggregateMask */

static int ParseCryptoPAnKey ( char *s, char *key ) {
int i, j;
char numstr[3];

	if ( strlen(s) == 32 ) {
		// Key is a string
		strncpy(key, s, 32);
		return 1;
	}

	tolower(s[1]);
	numstr[2] = 0;
	if ( strlen(s) == 66 && s[0] == '0' && s[1] == 'x' ) {
		j = 2;
		for ( i=0; i<32; i++ ) {
			if ( !isxdigit(s[j]) || !isxdigit(s[j+1]) )
				return 0;
			numstr[0] = s[j++];
			numstr[1] = s[j++];
			key[i] = strtol(numstr, NULL, 16);
		}
		return 1;
	}

	// It's an invalid key
	return 0;

} // End of ParseCryptoPAnKey

uint32_t process_data(char *wfile, int element_stat, int flow_stat, int sort_flows,
	printer_t print_header, printer_t print_record, time_t twin_start, time_t twin_end, 
	uint64_t limitflows, uint32_t *AggregateMasks, int anon) {
flow_header_t flow_header;					
flow_record_t *flow_record, *record_buffer;
uint16_t	cnt;
uint32_t	NumRecords;
time_t		win_start, win_end, first_seen, last_seen;
uint64_t	numflows, numbytes, numpackets;
int 		i, rfd, wfd, nffd, done, ret, request_size, *ftrue, do_stat, has_aggregate_mask, old_format;
uint64_t	numflows_tcp, numflows_udp, numflows_icmp, numflows_other;
uint64_t	numbytes_tcp, numbytes_udp, numbytes_icmp, numbytes_other;
uint64_t	numpackets_tcp, numpackets_udp, numpackets_icmp, numpackets_other;
char *string, sfile[255], tmpstring[64];

	if ( wfile && ( strcmp(wfile, "-") != 0 )) { // if we write a new file
		// write a new stat file
		snprintf(sfile, 254, "%s.stat", wfile);
		sfile[254] = 0;
	} else {
		sfile[0] = 0;	// no new stat file
	}

	// print flows later, when all records are processed and sorted
	if ( sort_flows ) {
		print_record = NULL;
		limitflows = 0;
	}

	// time window of all processed flows
	win_start = 0x7fffffff;
	win_end = 0;
	SetSeenTwin(0, 0);

	// time window of all matched flows
	first_seen = 0x7fffffff;
	last_seen  = 0;

	numflows = numbytes = numpackets = 0;
	numflows_tcp = numflows_udp = numflows_icmp = numflows_other = 0;
	numbytes_tcp = numbytes_udp = numbytes_icmp = numbytes_other = 0;
	numpackets_tcp = numpackets_udp = numpackets_icmp = numpackets_other = 0;

	do_stat = element_stat || flow_stat;

	// check for a special aggregate mask
	has_aggregate_mask = 0;
	for ( i=0; i<4; i++ ) 
		if ( AggregateMasks[i] )
			has_aggregate_mask = 1;

	// Get the first file handle
	rfd = GetNextFile(0, twin_start, twin_end);
	if ( rfd < 0 ) {
		if ( errno )
			perror("Can't open input file for reading");
		return numflows;
	}

	if ( wfile ) {
		wfd = strcmp(wfile, "-") == 0 ? STDOUT_FILENO : 
				open(wfile, O_CREAT | O_RDWR | O_TRUNC , S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
		if ( wfd < 0 ) {
			perror("Can't open output file for writing");
			if ( rfd ) 
				close(rfd);
			return numflows;
		}
	} else 
		wfd = 0;

	// allocate buffer suitable for netflow version
	record_buffer = (flow_record_t *) calloc(BuffNumRecords , FLOW_RECORD_LENGTH);

	ftrue = (int *) calloc(BuffNumRecords , sizeof(int));
	if ( !record_buffer || !ftrue ) {
		perror("Memory allocation error");
		close(rfd);
		if (wfd ) 
			close(wfd);
		return numflows;
	}

	done = 0;
	while ( !done ) {
		ret = read(rfd, &flow_header, FLOW_HEADER_LENGTH);
		if ( ret == 0 ) {
			rfd = GetNextFile(rfd, twin_start, twin_end);
			if ( rfd < 0 ) {
				if ( errno )
					perror("Can't open input file for reading");
				done = 1;
			} 
			continue;
		} else if ( ret == -1 ) {
			perror("Error reading data");
			close(rfd);
			if ( wfd ) 
				close(wfd);
			return numflows;
		}
		total_bytes += ret;
		if ( flow_header.version != FLOW_VERSION ) {
			fprintf(stdout, "Not a netflow v%i header\n", FLOW_VERSION);
			close(rfd);
			if ( wfd ) 
				close(wfd);
			return numflows;
		}
		if ( flow_header.count > MAX_RECORDS ) {
			fprintf(stderr, "Too many records %u ( > MAX_RECORDS )\n", flow_header.count);
			break;
		}

		NumRecords = flow_header.count;
		old_format = flow_header.layout_version != 1;

		request_size = NumRecords * FLOW_RECORD_LENGTH;
		ret = read(rfd, record_buffer, request_size);
		if ( ret == 0 ) {
			done = 1;
			break;
		} else if ( ret == -1 ) {
			perror("Error reading data");
			close(rfd);
			if ( wfd ) 
				close(wfd);
			return numflows;
		}
		if ( request_size != ret ) {
			fprintf(stderr, "Short read for netflow records: Expected %i, got %i bytes!\n",request_size, ret );
			break;
		}
		total_bytes += ret;

		// cnt is the number of blocks, which survived the filter
		// ftrue is an array of flags of the filter result
		cnt = 0;
		flow_record = record_buffer;
		for ( i=0; i < NumRecords; i++ ) {
			total_flows++;

			/* may be removed when old format died out */
			if ( old_format ) {
				flow_record->msec_first = 0;
				flow_record->msec_last  = 0;
			}

			// Time based filter
			// if no time filter is given, the result is always true
			ftrue[i] = twin_start && (flow_record->First < twin_start || flow_record->Last > twin_end) ? 0 : 1;
			ftrue[i] &= limitflows ? numflows < limitflows : 1;
			Engine->nfrecord = (uint32_t *)flow_record;

			// filter netflow record with user supplied filter
			if ( ftrue[i] ) 
				ftrue[i] = (*Engine->FilterEngine)(Engine);

			if ( ftrue[i] ) {
				// Update statistics
				switch (flow_record->prot) {
					case 1:
						numflows_icmp++;
						numpackets_icmp += flow_record->dPkts;
						numbytes_icmp   += flow_record->dOctets;
						break;
					case 6:
						numflows_tcp++;
						numpackets_tcp += flow_record->dPkts;
						numbytes_tcp   += flow_record->dOctets;
						break;
					case 17:
						numflows_udp++;
						numpackets_udp += flow_record->dPkts;
						numbytes_udp   += flow_record->dOctets;
						break;
					default:
						numflows_other++;
						numpackets_other += flow_record->dPkts;
						numbytes_other   += flow_record->dOctets;
				}
				numflows++;
				numpackets 	+= flow_record->dPkts;
				numbytes 	+= flow_record->dOctets;
				cnt++;

				if ( flow_record->First < first_seen )
					first_seen = flow_record->First;
				if ( flow_record->Last > last_seen ) 
					last_seen = flow_record->Last;

			}
			if ( flow_record->First < win_start )
				win_start = flow_record->First;
			if ( flow_record->Last > win_end ) 
				win_end = flow_record->Last;

			// increment pointer by number of bytes for netflow record
			flow_record = (flow_record_t *)((pointer_addr_t)flow_record + (pointer_addr_t)FLOW_RECORD_LENGTH);	

		} // for all records

		// check if we are done, due to -c option 
		if ( limitflows ) 
			done = numflows >= limitflows;

		// if no records are left after filtering, continue the read loop
		if ( cnt == 0 )
			continue;

		// Else we can process the header and any filtered records

		// set new count in v5 header
		flow_header.count = cnt;

		// write binary output if requested
		if ( wfd ) {
			ret = write(wfd, &flow_header, FLOW_HEADER_LENGTH);
			if ( ret < 0 ) {
				perror("Error writing data");
				close(rfd);
				if ( wfd ) 
					close(wfd);
				return numflows;
			}

			flow_record = record_buffer;
			for ( i=0; i < NumRecords; i++ ) {
				if ( ftrue[i] ) {
					if ( anon ) {
						flow_record->srcaddr = anonymize(flow_record->srcaddr);
						flow_record->dstaddr = anonymize(flow_record->dstaddr);
					}
					ret = write(wfd, flow_record, FLOW_RECORD_LENGTH);
					if ( ret < 0 ) {
						perror("Error writing data");
						close(rfd);
						return numflows;
					}
				}
				// increment pointer by number of bytes for netflow record
				flow_record = (flow_record_t *)((pointer_addr_t)flow_record + (pointer_addr_t)FLOW_RECORD_LENGTH);	
			}

		} else if ( do_stat ) {
			// Add records to netflow statistic hash
			flow_record = record_buffer;
			for ( i=0; i< NumRecords; i++ ) {
				if ( ftrue[i] ) {
					if ( has_aggregate_mask ) {
						flow_record->srcaddr &= AggregateMasks[0];
						flow_record->dstaddr &= AggregateMasks[1];
						flow_record->srcport &= AggregateMasks[2];
						flow_record->dstport &= AggregateMasks[3];
					}
					AddStat(&flow_header, flow_record, flow_stat, element_stat);
				}
				// increment pointer by number of bytes for netflow record
				flow_record = (flow_record_t *)((pointer_addr_t)flow_record + (pointer_addr_t)FLOW_RECORD_LENGTH);	
			}

		} else {
			// We print out the records somehow

			if ( print_header ) {
				print_header(&flow_header, 0, 0, 0, &string, anon);
				printf("%s", string);
			}

			flow_record = record_buffer;
			for ( i=0; i< NumRecords; i++ ) {
				if ( ftrue[i] ) {

					// if we need tp print out this record
					if ( print_record ) {
						print_record(flow_record, 1, (uint64_t)flow_record->dPkts, (uint64_t)flow_record->dOctets, &string, anon);
						if ( string ) {
							if ( limitflows ) {
								if ( (numflows <= limitflows) )
									printf("%s\n", string);
							} else 
								printf("%s\n", string);
						}
					}

					// if we need to sort the flows first -> insert into hash table
					// they get 
					if ( sort_flows ) 
						InsertFlow(flow_record);
				}

				// increment pointer by number of bytes for netflow record
				flow_record = (flow_record_t *)((pointer_addr_t)flow_record + (pointer_addr_t)FLOW_RECORD_LENGTH);	
			}
		}

	} // while

	if ( wfd ) 
		close(wfd);

	/* Statfile */
	if ( sfile[0] != 0 ) {
		nffd = open(sfile, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
		if ( nffd == -1 ) {
			perror("Can't open stat file: ");
			return numflows;
		}

		tmpstring[63] = 0;
		snprintf(tmpstring, 63, "Time: %u\n", GetStatTime());
		write(nffd, tmpstring, strlen(tmpstring)); 
		snprintf(tmpstring, 63, "Ident: %s\n", GetIdent());
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Flows: %llu\n", numflows);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Flows_tcp: %llu\n", numflows_tcp);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Flows_udp: %llu\n", numflows_udp);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Flows_icmp: %llu\n", numflows_icmp);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Flows_other: %llu\n", numflows_other);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Packets: %llu\n", numpackets);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Packets_tcp: %llu\n", numpackets_tcp);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Packets_udp: %llu\n", numpackets_udp);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Packets_icmp: %llu\n", numpackets_icmp);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Packets_other: %llu\n", numpackets_other);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Bytes: %llu\n", numbytes);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Bytes_tcp: %llu\n", numbytes_tcp);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Bytes_udp: %llu\n", numbytes_udp);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Bytes_icmp: %llu\n", numbytes_icmp);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Bytes_other: %llu\n", numbytes_other);
		write(nffd, tmpstring, strlen(tmpstring));
#if defined __OpenBSD__ || defined __FreeBSD__
		snprintf(tmpstring, 63, "First: %u\n", first_seen);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Last: %u\n", last_seen);
#else
		snprintf(tmpstring, 63, "First: %lu\n", first_seen);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Last: %lu\n", last_seen);
#endif
		write(nffd, tmpstring, strlen(tmpstring));

		close(nffd);
	} 

	free((void *)record_buffer);
	free((void *)ftrue);
	SetSeenTwin(win_start, win_end);

	return numflows;

} // End of process_data


int main( int argc, char **argv ) {
struct stat stat_buff;
printer_t 	print_header, print_record;
nfprof_t 	profile_data;
char 		c, *rfile, *Rfile, *Mdirs, *wfile, *ffile, *filter, *tstring, *stat_type;
char		*byte_limit_string, *packet_limit_string, *print_mode, *record_header;
char		*order_by, CryptoPAnKey[32];
int 		ffd, ret, element_stat, fdump;
int 		i, flow_stat, topN, aggregate, syntax_only, date_sorted, do_anonymize;
time_t 		t_start, t_end;
uint32_t	limitflows, matched_flows, AggregateMasks[4];

	rfile = Rfile = Mdirs = wfile = ffile = filter = tstring = stat_type = NULL;
	byte_limit_string = packet_limit_string = NULL;
	fdump = aggregate = 0;
	t_start = t_end = 0;
	syntax_only	    = 0;
	topN	        = 10;
	flow_stat       = 0;
	element_stat  	= 0;
	limitflows		= 0;
	matched_flows	= 0;
	date_sorted		= 0;
	total_bytes		= 0;
	total_flows		= 0;
	do_anonymize	= 0;

	print_mode      = NULL;
	print_header 	= NULL;
	print_record  	= NULL;
	record_header 	= "";

	SetStat_DefaultOrder("flows");

	for ( i=0; i<4; AggregateMasks[i++] = 0 ) ;

	while ((c = getopt(argc, argv, "aA:c:Ss:hn:f:r:w:K:M:mO:R:XZt:Vv:l:L:o:")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'a':
				aggregate = 1;
				break;
			case 'A':
				if ( !ParseAggregateMask(optarg, AggregateMasks) ) {
					fprintf(stderr, "Option -A requires a ',' separated list out of 'srcip dstip srcport dstport'\n");
					exit(255);
				}
				break;
			case 'X':
				fdump = 1;
				break;
			case 'Z':
				syntax_only = 1;
				break;
			case 'c':	
				limitflows = atoi(optarg);
				if ( !limitflows ) {
					fprintf(stderr, "Option -c needs a number > 0\n");
					exit(255);
				}
				break;
			case 's':
				stat_type = optarg;
				if ( !SetStat(stat_type, &element_stat, &flow_stat) ) {
					fprintf(stderr, "Stat '%s' unknown!\n", stat_type);
					exit(255);
				} 
				break;
			case 'V':
				printf("%s: Version: %s %s\n%s\n",argv[0], nfdump_version, nfdump_date, rcsid);
				exit(0);
				break;
			case 'l':
				packet_limit_string = optarg;
				break;
			case 'K':
				if ( !ParseCryptoPAnKey(optarg, CryptoPAnKey) ) {
					fprintf(stderr, "Invalid key '%s' for CryptoPAn!\n", optarg);
					exit(255);
				}
				do_anonymize = 1;
				break;
			case 'L':
				byte_limit_string = optarg;
				break;
			case 'f':
				ffile = optarg;
				break;
			case 't':
				tstring = optarg;
				break;
			case 'r':
				rfile = optarg;
				if ( strcmp(rfile, "-") == 0 )
					rfile = NULL;
				break;
			case 'm':
				date_sorted = 1;
				break;
			case 'M':
				Mdirs = optarg;
				break;
			case 'o':	// output mode
				print_mode = optarg;
				break;
			case 'O':	// stat order by
				order_by = optarg;
				if ( !SetStat_DefaultOrder(order_by) ) {
					fprintf(stderr, "Order '%s' unknown!\n", order_by);
					exit(255);
				}
				break;
			case 'R':
				Rfile = optarg;
				break;
			case 'v':
				fprintf(stderr, "Option no longer supported.\n");
				break;
			case 'w':
				wfile = optarg;
				break;
			case 'n':
				topN = atoi(optarg);
				if ( topN < 0 ) {
					fprintf(stderr, "TopnN number %i out of range\n", topN);
					exit(255);
				}
				break;
			case 'S':	// Compatibility with pre 1.4 -S option
				if ( !SetStat("record/packets/bytes", &element_stat, &flow_stat) ) {
					// Should never happen
					fprintf(stderr, "Software Error!\n");
					exit(255);
				} 
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

	if ( rfile && Rfile ) {
		fprintf(stderr, "-r and -R are mutually exclusive. Plase specify either -r or -R\n");
		exit(255);
	}
	if ( Mdirs && !(rfile || Rfile) ) {
		fprintf(stderr, "-M needs either -r or -R to specify the file or file list. Add '-R .' for all files in the directories.\n");
		exit(255);
	}


	// handle print mode
	if ( !print_mode )
		print_mode = DefaultMode;

	i = 0;
	while ( printmap[i].printmode ) {
		if ( strncasecmp(print_mode, printmap[i].printmode, MAXMODELEN) == 0 ) {
			print_record = printmap[i].func;
			record_header = printmap[i].HeaderLine;
			if ( date_sorted && ( printmap[i].sorted == 0 ) ) {
				date_sorted = 0;
				fprintf(stderr, "Option -m does not make sense with output mode '%s'\n", print_mode);
			}
			break;
		}
		i++;
	}

	if ( !print_record ) {
		fprintf(stderr, "Unknown output mode '%s'\n", print_mode);
		exit(255);
	}

	// this is the only case, where headers are printed.
	if ( strncasecmp(print_mode, "raw", 16) == 0 )
		print_header = flow_header_raw;
	
	if ( aggregate && (flow_stat || element_stat) ) {
		aggregate = 0;
		fprintf(stderr, "Command line switch -s or -S overwrites -a\n");
	}

	if ( !filter && ffile ) {
		if ( stat(ffile, &stat_buff) ) {
			fprintf(stderr, "Can't stat filter file '%s': %s\n", ffile, strerror(errno));
			exit(255);
		}
		filter = (char *)malloc(stat_buff.st_size+1);
		if ( !filter ) {
			perror("Memory allocation error");
			exit(255);
		}
		ffd = open(ffile, O_RDONLY);
		if ( ffd < 0 ) {
			fprintf(stderr, "Can't open filter file '%s': %s\n", ffile, strerror(errno));
			exit(255);
		}
		ret = read(ffd, (void *)filter, stat_buff.st_size);
		if ( ret < 0   ) {
			perror("Error reading filter file");
			close(ffd);
			exit(255);
		}
		total_bytes += ret;
		filter[stat_buff.st_size] = 0;
		close(ffd);
	}

	// if no filter is given, set the default ip filter which passes through every flow
	if ( !filter ) 
		filter = "any";

	Engine = CompileFilter(filter);
	if ( !Engine ) 
		exit(254);

	if ( fdump ) {
		printf("StartNode: %i Engine: %s\n", Engine->StartNode, Engine->Extended ? "Extended" : "Fast");
		DumpList(Engine);
		exit(0);
	}

	if ( syntax_only )
		exit(0);

	if ((aggregate || flow_stat)  && ( topN > 1000) ) {
		printf("Topn N > 1000 only allowed for IP statistics");
		exit(255);
	}


	if ((aggregate || flow_stat || date_sorted)  && !Init_FlowTable(HashBits, NumPrealloc) )
			exit(250);

	if (element_stat && !Init_StatTable(HashBits, NumPrealloc) )
			exit(250);

	SetLimits(element_stat || aggregate || flow_stat, packet_limit_string, byte_limit_string);

	SetupInputFileSequence(Mdirs, rfile, Rfile);

	if ( tstring ) {
		if ( !ScanTimeFrame(tstring, &t_start, &t_end) )
			exit(255);
	}


	if ( !(flow_stat || element_stat || wfile ) && record_header ) 
		printf("%s\n", record_header);

	if (do_anonymize)
		PAnonymizer_Init((uint8_t *)CryptoPAnKey);

	nfprof_start(&profile_data);
	matched_flows = process_data(wfile, element_stat, aggregate || flow_stat, date_sorted,
						print_header, print_record, t_start, t_end, 
						limitflows, AggregateMasks, do_anonymize);
	nfprof_end(&profile_data, total_flows);

	if (aggregate) {
		ReportAggregated(print_record, limitflows, date_sorted, do_anonymize);
		Dispose_Tables(1, 0); // Free the FlowTable
	}

	if (flow_stat || element_stat) {
		ReportStat(record_header, print_record, topN, flow_stat, element_stat, do_anonymize);
		Dispose_Tables(flow_stat, element_stat);
	} 

	if ( date_sorted && !(aggregate || flow_stat || element_stat) ) {
		PrintSortedFlows(print_record, limitflows, do_anonymize);
		Dispose_Tables(1, 0);	// Free the FlowTable
	}

	if ( !wfile ) {
		if (do_anonymize)
			printf("IP addresses anonymized\n");
		printf("Time window: %s\n", TimeString());
		printf("Flows analysed: %u matched: %u, Bytes read: %llu\n", total_flows, matched_flows, total_bytes);
		nfprof_print(&profile_data, stdout);
	}
	return 0;
}
