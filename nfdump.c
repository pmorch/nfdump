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
 *  $Id: nfdump.c 24 2005-04-01 12:07:30Z peter $
 *
 *  $LastChangedRevision: 24 $
 *	
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

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif


#include "netflow_v5.h"
#include "nf_common.h"
#include "nftree.h"
#include "nfdump.h"
#include "nfstat.h"
#include "version.h"
#include "util.h"


/* hash parameters */
#define HashBits 20
#define NumPrealloc 128000


/* Global Variables */
FilterEngine_data_t	*Engine;
uint32_t			byte_limit, packet_limit;
int 				byte_mode, packet_mode;

/* Local Variables */
static char const *rcsid 		  = "$Id: nfdump.c 24 2005-04-01 12:07:30Z peter $";
static uint64_t total_bytes;
static uint32_t total_flows;

// Header Legend
#define HEADER_LINE "Date flow start        Len Proto    Src IP Addr:Port         Dst IP Addr:Port  Packets    Bytes"
//                   Aug 20 2004 10:25:00   300 TCP      172.16.1.66:1024  ->    172.16.19.18:25        101   101  B

#define HEADER_LINE_LONG "Date flow start        Len Proto    Src IP Addr:Port         Dst IP Addr:Port   Flags Tos Packets    Bytes"
//                        Aug 20 2004 10:25:00   300 TCP      172.16.1.66:1024  ->    172.16.19.18:25    ......   0     101   101  B

// Assign print functions for all output options -o
// Teminated with a NULL record
struct printmap_s {
	char		*printmode;		// name of mode
	int			sorted;			// does it make sense to sort the output in this mode?
	printer_t	func;			// name of the function, which prints the record
	char		*HeaderLine;	// Header line for each output format, if needed. NULL otherwise
} printmap[] = {
	{ "extended",	0, netflow_v5_record_to_block,     NULL },
	{ "line", 		1, netflow_v5_record_to_line,      HEADER_LINE },
	{ "long", 		1, netflow_v5_record_to_line_long, HEADER_LINE_LONG },
	{ "pipe", 		0, netflow_v5_record_to_pipe,      NULL },
	{ "NULL",		0, NULL,                           NULL }
};

#define DefaultMode "line"

// compare at most 16 chars
#define MAXMODELEN	16	

// all records should be version 5
#define NETFLOW_VERSION 5

/* Function Prototypes */
static void usage(char *name);

static int ParseAggregateMask( char *arg, uint32_t *AggregateMasks );

static uint32_t process_data(char *wfile, int any_stat, int flow_stat, int sort_flows,
	printer_t print_header, printer_t print_record,
	time_t twin_start, time_t twin_end, uint64_t limitflows, uint32_t *AggregateMasks);

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
					"\t\t line     Standard output line format.\n"
					"\t\t long     Standard output line format with additional fields.\n"
					"\t\t extended Verbose record dump including netflow headers.\n"
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

static uint32_t process_data(char *wfile, int any_stat, int flow_stat, int sort_flows,
	printer_t print_header, printer_t print_record,
	time_t twin_start, time_t twin_end, uint64_t limitflows, uint32_t *AggregateMasks) {
nf_header_t nf_header;					
nf_record_t *nf_record, *record_buffer;
uint16_t	cnt;
uint32_t	NumRecords;
time_t		win_start, win_end, first_seen, last_seen;
uint64_t	numflows, numbytes, numpackets;
int i, rfd, wfd, nffd, done, ret, *ftrue, do_stat, has_aggregate_mask;
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

	first_seen = win_start = 0xffffffff;
	last_seen = win_end = 0;
	SetSeenTwin(0, 0);
	numflows = numbytes = numpackets = 0;
	numflows_tcp = numflows_udp = numflows_icmp = numflows_other = 0;
	numbytes_tcp = numbytes_udp = numbytes_icmp = numbytes_other = 0;
	numpackets_tcp = numpackets_udp = numpackets_icmp = numpackets_other = 0;

	do_stat = any_stat || flow_stat;

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
	record_buffer = (nf_record_t *) calloc(BuffNumRecords , NETFLOW_V5_RECORD_LENGTH);

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
		ret = read(rfd, &nf_header, NETFLOW_V5_HEADER_LENGTH);
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
		if ( nf_header.version != NETFLOW_VERSION ) {
			fprintf(stdout, "Not a netflow v%i header\n", NETFLOW_VERSION);
			close(rfd);
			if ( wfd ) 
				close(wfd);
			return numflows;
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
			if ( wfd ) 
				close(wfd);
			return numflows;
		}
		total_bytes += ret;

		// cnt is the number of blocks, which survived the filter
		// ftrue is an array of flags of the filter result
		cnt = 0;
		nf_record = record_buffer;
		for ( i=0; i < NumRecords; i++ ) {
			total_flows++;
			// Time filter
			// if no time filter is given, the result is always true
			ftrue[i] = twin_start ? nf_record->First >= twin_start && nf_record->Last <= twin_end : 1;
			ftrue[i] &= limitflows ? numflows < limitflows : 1;
			Engine->nfrecord = (uint32_t *)nf_record;

			// filter netflow record with user supplied filter
			if ( ftrue[i] ) 
				ftrue[i] = (*Engine->FilterEngine)(Engine);

			if ( ftrue[i] ) {
				// Update statistics
				switch (nf_record->prot) {
					case 1:
						numflows_icmp++;
						numpackets_icmp += nf_record->dPkts;
						numbytes_icmp   += nf_record->dOctets;
						break;
					case 6:
						numflows_tcp++;
						numpackets_tcp += nf_record->dPkts;
						numbytes_tcp   += nf_record->dOctets;
						break;
					case 17:
						numflows_udp++;
						numpackets_udp += nf_record->dPkts;
						numbytes_udp   += nf_record->dOctets;
						break;
					default:
						numflows_other++;
						numpackets_other += nf_record->dPkts;
						numbytes_other   += nf_record->dOctets;
				}
				numflows++;
				numpackets 	+= nf_record->dPkts;
				numbytes 	+= nf_record->dOctets;
				cnt++;

				// Uptime time window of matched netflow data
				if (nf_record->First < first_seen )
					first_seen = nf_record->First;
				if (nf_record->Last > last_seen )
					last_seen = nf_record->Last;
			}

			// Update processed time window
			if (nf_record->First < win_start )
				win_start = nf_record->First;
			if (nf_record->Last > win_end )
				win_end = nf_record->Last;

			// increment pointer by number of bytes for netflow record
			nf_record = (nf_record_t *)((pointer_addr_t)nf_record + (pointer_addr_t)NETFLOW_V5_RECORD_LENGTH);	

		} // for all records

		// check if we are done, due to -c option 
		if ( limitflows ) 
			done = numflows >= limitflows;

		// if no records are left after filtering, continue the read loop
		if ( cnt == 0 )
			continue;

		// Else we can process the header and any filtered records

		// set new count in v5 header
		nf_header.count = cnt;

		// write binary output if requested
		if ( wfd ) {
			ret = write(wfd, &nf_header, NETFLOW_V5_HEADER_LENGTH);
			if ( ret < 0 ) {
				perror("Error writing data");
				close(rfd);
				if ( wfd ) 
					close(wfd);
				return numflows;
			}

			nf_record = record_buffer;
			for ( i=0; i < NumRecords; i++ ) {
				if ( ftrue[i] ) {
					ret = write(wfd, nf_record, NETFLOW_V5_RECORD_LENGTH);
					if ( ret < 0 ) {
						perror("Error writing data");
						close(rfd);
						return numflows;
					}
				}
				// increment pointer by number of bytes for netflow record
				nf_record = (nf_record_t *)((pointer_addr_t)nf_record + (pointer_addr_t)NETFLOW_V5_RECORD_LENGTH);	
			}

		} else if ( do_stat ) {
			// Add records to netflow statistic hash
			nf_record = record_buffer;
			for ( i=0; i< NumRecords; i++ ) {
				if ( ftrue[i] ) {
					if ( has_aggregate_mask ) {
						nf_record->srcaddr &= AggregateMasks[0];
						nf_record->dstaddr &= AggregateMasks[1];
						nf_record->srcport &= AggregateMasks[2];
						nf_record->dstport &= AggregateMasks[3];
					}
					AddStat(&nf_header, nf_record, flow_stat, any_stat);
				}
				// increment pointer by number of bytes for netflow record
				nf_record = (nf_record_t *)((pointer_addr_t)nf_record + (pointer_addr_t)NETFLOW_V5_RECORD_LENGTH);	
			}

		} else {
			// We print out the records somehow

			if ( print_header ) {
				print_header(&nf_header, &string);
				printf("%s", string);
			}

			nf_record = record_buffer;
			for ( i=0; i< NumRecords; i++ ) {
				if ( ftrue[i] ) {

					// if we need tp print out this record
					if ( print_record ) {
						print_record(nf_record, &string);
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
						list_insert(nf_record);
				}

				// increment pointer by number of bytes for netflow record
				nf_record = (nf_record_t *)((pointer_addr_t)nf_record + (pointer_addr_t)NETFLOW_V5_RECORD_LENGTH);	
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
		snprintf(tmpstring, 63, "First: %lu\n", first_seen);
		write(nffd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 63, "Last: %lu\n", last_seen);
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
char 		c, *rfile, *Rfile, *Mdirs, *wfile, *ffile, *filter, *tstring, *stat_type;
char		*byte_limit_string, *packet_limit_string, *print_mode, *record_header;
int 		ffd, ret, any_stat, fdump;
int 		i, flow_stat, topN, aggregate, syntax_only, date_sorted;
time_t 		t_start, t_end;
uint32_t	limitflows, matched_flows, AggregateMasks[4];

	rfile = Rfile = Mdirs = wfile = ffile = filter = tstring = stat_type = NULL;
	byte_limit_string = packet_limit_string = NULL;
	fdump = aggregate = 0;
	t_start = t_end = 0;
	syntax_only	    = 0;
	topN	        = 10;
	flow_stat       = 0;
	any_stat   		= 0;
	limitflows		= 0;
	matched_flows	= 0;
	date_sorted		= 0;
	total_bytes		= 0;
	total_flows		= 0;

	print_mode      = NULL;
	print_header 	= NULL;
	print_record  	= NULL;
	record_header 	= "";

	for ( i=0; i<4; AggregateMasks[i++] = 0 ) ;

	while ((c = getopt(argc, argv, "aA:c:Ss:hn:f:r:w:M:mR:XZt:Vv:l:L:o:")) != EOF) {
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
				break;
			case 'V':
				printf("%s: Version: %s %s\n%s\n",argv[0], nfdump_version, nfdump_date, rcsid);
				exit(0);
				break;
			case 'l':
				packet_limit_string = optarg;
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
			case 'S':
				flow_stat = 1;
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
	if ( strncasecmp(print_mode, "extended", 16) == 0 )
		print_header = netflow_v5_header_to_string;
	
	if ( stat_type ) {
		if ( Set_StatType(stat_type) ) {
			fprintf(stderr, "Unknown statistics '%s'\n", stat_type);
			exit(255);
		} else {
			any_stat = 1;
		}
	}

	if ( aggregate && (flow_stat || any_stat) ) {
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

	if (any_stat && !Init_StatTable(HashBits, NumPrealloc) )
			exit(250);

	SetLimits(any_stat || aggregate || flow_stat, packet_limit_string, byte_limit_string);

	SetupInputFileSequence(Mdirs, rfile, Rfile);

	if ( tstring ) {
		if ( !ScanTimeFrame(tstring, &t_start, &t_end) )
			exit(255);
	}

	if ( !(flow_stat || any_stat || wfile ) && record_header ) 
		printf("%s\n", record_header);

	matched_flows = process_data(wfile, any_stat, aggregate || flow_stat, date_sorted,
						print_header, print_record, t_start, t_end, limitflows, AggregateMasks);

	if ( !wfile )
		printf("Flows analysed: %u matched: %u, Bytes read: %llu\n", total_flows, matched_flows, total_bytes);

	if (aggregate) {
		ReportAggregated(print_record, limitflows, date_sorted);
		Dispose_Tables(1, 0); // Free the FlowTable
	}

	if (flow_stat || any_stat) {
		ReportStat(record_header, print_record, topN, flow_stat, any_stat);
		Dispose_Tables(flow_stat, any_stat);
	} else if ( !wfile )
		printf("Time window: %s\n", TimeString());

	if ( date_sorted && !(aggregate || flow_stat || any_stat) ) {
		PrintSortedFlows(print_record, limitflows);
		Dispose_Tables(1, 0);	// Free the FlowTable
	}

	return 0;
}
