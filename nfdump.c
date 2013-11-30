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
 *  $Id: nfdump.c 4 2004-09-22 07:22:28Z peter $
 *
 *  $LastChangedRevision: 4 $
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
#include "netflow_v7.h"
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
static char const *rcsid 		  = "$Id: nfdump.c 4 2004-09-22 07:22:28Z peter $";
static int netflow_version;
static uint64_t total_bytes;

/* defines */
enum { PRINT_NONE = 0, PRINT_LONG, PRINT_LINE, PRINT_PACKED, PRINT_DATE_SORTED };

/* Function Prototypes */
static void usage(char *name);

static uint32_t process_data(char *wfile, int print_mode, int ip_stat, int flow_stat, time_t twin_start, time_t twin_end, uint32_t limitflows);


/* Functions */
static void usage(char *name) {
		printf("usage %s [options] [\"filter\"]\n"
					"-h\t\tthis text you see right here\n"
					"-V\t\tPrint version and exit.\n"
					"-v <version>\tset netflow version (default 5)\n"
					"-a\t\tAggrigate netflow data.\n"
					"-r\t\tread input from file\n"
					"-w\t\twrite output to file\n"
					"-f\t\tread netflow filter from file\n"
					"-n\t\tDefine number of top N. \n"
					"-c\t\tLimit number of records to display\n"
					"-S\t\tGenerate netflow statistics info.\n"
					"-s\t\tGenerate SRC IP statistics.\n"
					"-s -s\t\tGenerate DST IP statistics.\n"
					"-s -s -s\tGenerate SRC/DST IP statistics.\n"
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
					"-p\t\tPrint netflow records in packed format, '|' separated.\n"
					"-E\t\tPrint netflow data in extended format.\n"
					"-X\t\tDump Filtertable and exit (debug option).\n"
					"-Z\t\tCheck filter syntax and exit.\n"
					"-t <time>\ttime window for filtering packets\n"
					"\t\tyyyy/MM/dd.hh:mm:ss[-yyyy/MM/dd.hh:mm:ss]\n", name);
} /* usage */

static uint32_t process_data(char *wfile, int print_mode, int ip_stat, int flow_stat, time_t twin_start, time_t twin_end, uint32_t limitflows) {
nf_header_t nf_header;					// v5 v7 common header struct
nf_record_t *nf_record, *record_buffer;	// v5 v7 common record fields for processing
uint16_t	cnt;
uint32_t	NumRecords;
time_t		first_seen, last_seen;
uint64_t	numflows, numbytes, numpackets;
int i, rfd, wfd, nffd, done, ret, *ftrue, src_ip_stat, dst_ip_stat, do_stat;
uint16_t 	header_length, record_length;
uint64_t	numflows_tcp, numflows_udp, numflows_icmp, numflows_other;
uint64_t	numbytes_tcp, numbytes_udp, numbytes_icmp, numbytes_other;
uint64_t	numpackets_tcp, numpackets_udp, numpackets_icmp, numpackets_other;
char *string, sfile[255], tmpstring[64];
printer_t	print_header_string, print_record_string, print_record_line, print_record_packed;

	if ( wfile && ( strcmp(wfile, "-") != 0 )) { // if we write a new file
		// write a new stat file
		snprintf(sfile, 254, "%s.stat", wfile);
		sfile[254] = 0;
	} else {
		sfile[0] = 0;	// no new stat file
	}

	switch (netflow_version) {
		case 5: 
				header_length = NETFLOW_V5_HEADER_LENGTH;
				record_length = NETFLOW_V5_RECORD_LENGTH;
				print_header_string  = netflow_v5_header_to_string;
				print_record_string  = netflow_v5_record_to_string;
				print_record_line    = netflow_v5_record_to_line;
				print_record_packed  = netflow_v5_record_packed;
			break;
		case 7: 
				header_length = NETFLOW_V7_HEADER_LENGTH;
				record_length = NETFLOW_V7_RECORD_LENGTH;
				print_header_string  = netflow_v7_header_to_string;
				print_record_string  = netflow_v7_record_to_string;
				print_record_line    = netflow_v7_record_to_line;
				print_record_packed  = netflow_v7_record_packed;
			break;
		default:
				header_length = NETFLOW_V5_HEADER_LENGTH;
				record_length = NETFLOW_V5_RECORD_LENGTH;
				print_header_string  = netflow_v5_header_to_string;
				print_record_string  = netflow_v5_record_to_string;
				print_record_line    = netflow_v5_record_to_line;
				print_record_packed  = netflow_v5_record_packed;
	}

	first_seen = 0xffffffff;
	last_seen = 0;
	SetSeenTwin(0, 0);
	numflows = numbytes = numpackets = 0;
	numflows_tcp = numflows_udp = numflows_icmp = numflows_other = 0;
	numbytes_tcp = numbytes_udp = numbytes_icmp = numbytes_other = 0;
	numpackets_tcp = numpackets_udp = numpackets_icmp = numpackets_other = 0;

	src_ip_stat = ip_stat == 1 || ip_stat == 3;
	dst_ip_stat = ip_stat == 2 || ip_stat == 3;
	do_stat = ip_stat != 0 || flow_stat;

	// Get the first file handle
	rfd = GetNextFile(0, twin_start, twin_end);
	if ( rfd < 0 ) {
		if ( errno )
			perror("Can't open file for reading");
		return numflows;
	}

	if ( wfile ) {
		wfd = strcmp(wfile, "-") == 0 ? STDOUT_FILENO : 
				open(wfile, O_CREAT | O_RDWR | O_TRUNC , S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
		if ( wfd < 0 ) {
			perror("Can't open file for writing");
			if ( rfd ) 
				close(rfd);
			return numflows;
		}
	} else 
		wfd = 0;

	// allocate buffer suitable for netflow version
	record_buffer = (nf_record_t *) calloc(BuffNumRecords , record_length);

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
		ret = read(rfd, &nf_header, header_length);
		if ( ret == 0 ) {
			rfd = GetNextFile(rfd, twin_start, twin_end);
			if ( rfd < 0 ) {
				if ( errno )
					perror("Can't open file for reading");
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
		if ( nf_header.version != netflow_version ) {
			fprintf(stdout, "Not a netflow v%i header\n", netflow_version);
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

		ret = read(rfd, record_buffer, NumRecords * record_length);
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
			// Time filter
			// if no time filter is given, the result is always true
			ftrue[i] = twin_start ? nf_record->First >= twin_start && nf_record->Last <= twin_end : 1;
			ftrue[i] &= limitflows ? numflows < limitflows : 1;
			Engine->nfrecord = (uint32_t *)nf_record;


			// netflow record filter
			if ( ftrue[i] ) 
				ftrue[i] = (*Engine->FilterEngine)(Engine);

			if ( do_stat && ftrue[i] )
				AddStat(&nf_header, nf_record, flow_stat, src_ip_stat, dst_ip_stat);
			if ( ftrue[i] ) {
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
				if (nf_record->First < first_seen )
					first_seen = nf_record->First;
				if (nf_record->Last > last_seen )
					last_seen = nf_record->Last;
				cnt++;
			}
			// increment pointer by number of bytes for netflow record
			nf_record = (nf_record_t *)((pointer_addr_t)nf_record + (pointer_addr_t)record_length);	
		}

		// set new count in v5 header
		nf_header.count = cnt;

		// dump header and records only, if any block is left
		if ( cnt ) {
			if ( wfd ) {
				/* write to file */
				ret = write(wfd, &nf_header, header_length);
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
						ret = write(wfd, nf_record, record_length);
						if ( ret < 0 ) {
							perror("Error writing data");
							close(rfd);
							return numflows;
						}
					}
					// increment pointer by number of bytes for netflow record
					nf_record = (nf_record_t *)((pointer_addr_t)nf_record + (pointer_addr_t)record_length);	
				}

			} else if ( !do_stat ) {
				/* write to stdout */
				if ( print_mode == PRINT_LONG ) {
					print_header_string(&nf_header, &string);
					printf("%s", string);
				}

				nf_record = record_buffer;
				for ( i=0; i< NumRecords; i++ ) {
					if ( ftrue[i] ) {
						switch ( print_mode ) {
							case PRINT_LONG:
								print_record_string(nf_record, &string);
								break;
							case PRINT_LINE:
								print_record_line(nf_record, &string);
								break;
							case PRINT_PACKED:
								print_record_packed(nf_record, &string);
								break;
							case PRINT_DATE_SORTED:
								list_insert(nf_record);
								string = NULL;
								break;
							default:
								string = NULL;
						}

						if ( string ) {
							if ( limitflows ) {
								if ( (numflows <= limitflows) && string )
									printf("%s", string);
							} else 
								printf("%s", string);
						}

					}
					// increment pointer by number of bytes for netflow record
					nf_record = (nf_record_t *)((pointer_addr_t)nf_record + (pointer_addr_t)record_length);	
				}

			} // else 
		} // if cnt 
		if ( limitflows ) 
			done = numflows >= limitflows;

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
	SetSeenTwin(first_seen, last_seen);

	return numflows;

} // End of process_data


int main( int argc, char **argv ) {
struct stat stat_buff;
char 		c, *rfile, *Rfile, *Mdirs, *wfile, *ffile, *filter, *tstring;
char		*byte_limit_string, *packet_limit_string;
int 		ffd, ret, ip_stat, print_mode, fdump;
int 		flow_stat, topN, aggrigate, syntax_only, date_sorted;
time_t 		t_start, t_end;
uint32_t	limitflows, total_flows;

	rfile = Rfile = Mdirs = wfile = ffile = filter = tstring = NULL;
	byte_limit_string = packet_limit_string = NULL;
	fdump = aggrigate = 0;
	t_start = t_end = 0;
	print_mode      = PRINT_LINE;
	syntax_only	    = 0;
	topN	        = 10;
	flow_stat       = 0;
	ip_stat   		= 0;
	limitflows		= 0;
	total_flows		= 0;
	date_sorted		= 0;
	netflow_version	= 5;
	total_bytes		= 0;
	while ((c = getopt(argc, argv, "ac:Sshn:f:r:w:M:mR:XZt:VEpv:l:L:")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'a':
				aggrigate = 1;
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
			case 'E':
				print_mode = PRINT_LONG;
				break;
			case 'p':
				print_mode = PRINT_PACKED;
				break;
			case 's':
				ip_stat++;
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
			case 'R':
				Rfile = optarg;
				break;
			case 'v':
				netflow_version = atoi(optarg);
				if ( netflow_version != 5 && netflow_version != 7 ) {
					fprintf(stderr, "ERROR: Supports only netflow version 5 and 7\n");
					exit(255);
				}
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

	if ( Mdirs && ( !rfile && !Rfile ) ) {
		fprintf(stderr, "Option -M requires -R or -r. Set -R . for all files.\n");
		exit(255);
	}

	if ( aggrigate && (flow_stat || ip_stat) ) {
		aggrigate = 0;
		fprintf(stderr, "Command line switch -s or -S overwrites -a\n");
	}

	// date_sorted does not make sense in any other mode
	if ( date_sorted && print_mode != PRINT_LINE )
		date_sorted = 0;

	if ( date_sorted && 
		!(aggrigate || flow_stat || ip_stat) &&
		(print_mode == PRINT_LINE) ) {
			print_mode = PRINT_DATE_SORTED;
	}

	if ( !filter && ffile ) {
		if ( stat(ffile, &stat_buff) ) {
			perror("Can't stat file");
			exit(255);
		}
		filter = (char *)malloc(stat_buff.st_size+1);
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

	if ((aggrigate || flow_stat)  && ( topN > 1000) ) {
		printf("Topn N > 1000 only allowed for IP statistics");
		exit(255);
	}


	if ((aggrigate || flow_stat || date_sorted)  && !Init_FlowTable(HashBits, NumPrealloc) )
			exit(250);

	if (ip_stat && !Init_IPTable(HashBits, NumPrealloc) )
			exit(250);

	SetLimits(packet_limit_string, byte_limit_string);

	SetupInputFileSequence(Mdirs, rfile, Rfile);

	if ( tstring ) {
		if ( !ScanTimeFrame(tstring, &t_start, &t_end) )
			exit(255);
	}

	total_flows = process_data(wfile, print_mode, ip_stat, aggrigate || flow_stat, t_start, t_end, limitflows);
	if ( !wfile )
		printf("Analysed flows: %u, Bytes read: %llu\n", total_flows, total_bytes);

	if (aggrigate) {
		ReportAggregated(limitflows, date_sorted);
		Dispose_Tables(1, 0); // Free the FlowTable
	}

	if (flow_stat || ip_stat) {
		ReportStat(topN, flow_stat, ip_stat);
		Dispose_Tables(flow_stat, ip_stat);
	} else 
		if ( !wfile )
			printf("Time window: %s\n", TimeString());

	if ( date_sorted && !(aggrigate || flow_stat || ip_stat) ) {
		PrintSortedFlows();
		Dispose_Tables(1, 0);	// Free the FlowTable
	}

	return 0;
}
