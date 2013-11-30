/*
 *  nfprofile : Reads netflow data from files, saved by nfcapd
 *  		 	Data can be view, filtered and saved to 
 *  		 	files.
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
 *  $Id: nfprofile.c 14 2004-12-07 15:26:02Z peter $
 *
 *  $LastChangedRevision: 14 $
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
#include "version.h"
#include "nf_common.h"
#include "nftree.h"
#include "nfdump.h"
#include "nfstat.h"
#include "util.h"
#include "profile.h"

/* hash parameters */
#define HashBits 20
#define NumPrealloc 128000

/* Global Variables */
uint32_t	byte_limit, packet_limit;
int 		byte_mode, packet_mode;

/* Local Variables */
static char const *rcsid 		  = "$Id: nfprofile.c 14 2004-12-07 15:26:02Z peter $";

#define NETFLOW_VERSION 5

/* Function Prototypes */
static void usage(char *name);

static void process_data(profileinfo_t *profiles, unsigned int num_profiles, time_t twin_start, time_t twin_end);


/* Functions */
static void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tthis text you see right here\n"
					"-V\t\tPrint version and exit.\n"
					"-r\t\tread input from file\n"
					"-f\t\tfilename with filter syntaxfile\n"
					"-p\t\tprofile dir.\n"
					"-s\t\tprofile subdir.\n"
					"-Z\t\tCheck filter syntax and exit.\n"
					"-t <time>\ttime window for filtering packets\n"
					"-q\t\tSuppress profile working info\n"
					"\t\tyyyy/MM/dd.hh:mm:ss[-yyyy/MM/dd.hh:mm:ss]\n", name);
} /* usage */

static void process_data(profileinfo_t *profiles, unsigned int num_profiles, time_t twin_start, time_t twin_end) {
nf_header_t nf_header;
nf_record_t *nf_record, *record_buffer;
FilterEngine_data_t	*engine;
uint32_t	NumRecords;
uint32_t	first_seen, last_seen;
int i, j, rfd, done, ret ;

	rfd = GetNextFile(0, twin_start, twin_end);
	if ( rfd < 0 ) {
		if ( errno ) 
			perror("Can't open file for reading");
		return;
	}

	// allocate buffer suitable for netflow version
	record_buffer = (nf_record_t *) calloc(BuffNumRecords , NETFLOW_V5_RECORD_LENGTH);
	if ( !record_buffer ) {
		perror("Memory allocation error");
		close(rfd);
		return;
	}

	first_seen	= 0xffffffff;
	last_seen	= 0;
	SetSeenTwin(0, 0);

	done = 0;
	while ( !done ) {
		ret = read(rfd, &nf_header, NETFLOW_V5_HEADER_LENGTH);
		if ( ret == 0 ) {
			done = 1;
			if ( rfd ) // unless stdiin
				close(rfd);
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

		nf_record = record_buffer;
		for ( j=0; j < num_profiles; j++ ) {
			// cnt is the number of blocks, which survived the filter
			// ftrue is an array of flags of the filter result
			profiles[j].cnt = 0;
			for ( i=0; i < NumRecords; i++ ) {
				// Time filter
				// if no time filter is given, the result is always true
				profiles[j].ftrue[i] = twin_start ? nf_record->First >= twin_start && nf_record->Last <= twin_end : 1;
				engine = profiles[j].engine;
				engine->nfrecord = (uint32_t *)nf_record;
	
				// netflow record filter
				if ( profiles[j].ftrue[i] ) 
					profiles[j].ftrue[i] = (*engine->FilterEngine)(engine);
	
				if ( profiles[j].ftrue[i] ) {
					switch (nf_record->prot) {
						case 1:
							profiles[j].numflows_icmp++;
							profiles[j].numpackets_icmp += nf_record->dPkts;
							profiles[j].numbytes_icmp   += nf_record->dOctets;
							break;
						case 6:
							profiles[j].numflows_tcp++;
							profiles[j].numpackets_tcp += nf_record->dPkts;
							profiles[j].numbytes_tcp   += nf_record->dOctets;
							break;
						case 17:
							profiles[j].numflows_udp++;
							profiles[j].numpackets_udp += nf_record->dPkts;
							profiles[j].numbytes_udp   += nf_record->dOctets;
							break;
						default:
							profiles[j].numflows_other++;
							profiles[j].numpackets_other += nf_record->dPkts;
							profiles[j].numbytes_other   += nf_record->dOctets;
					}
					profiles[j].numflows++;
					profiles[j].numpackets 	+= nf_record->dPkts;
					profiles[j].numbytes 	+= nf_record->dOctets;
					if ( nf_record->First < first_seen )
						first_seen = nf_record->First;
					if ( nf_record->Last > last_seen )
						last_seen = nf_record->Last;
					profiles[j].cnt++;
				}
				// increment pointer by number of bytes for netflow record
				nf_record = (void *)((pointer_addr_t)nf_record + NETFLOW_V5_RECORD_LENGTH);
			}

			// set new count in v5 header
			nf_header.count = profiles[j].cnt;
	
			// dump header and records only, if any block is left
			if ( profiles[j].cnt ) {
				/* write to file */
				ret = write(profiles[j].wfd, &nf_header, NETFLOW_V5_HEADER_LENGTH);
				if ( ret < 0 ) {
					perror("Error writing data");
					continue;
				}
				nf_record = record_buffer;
				for ( i=0; i < NumRecords; i++ ) {
					if ( profiles[j].ftrue[i] ) {
						ret = write(profiles[j].wfd, nf_record, NETFLOW_V5_RECORD_LENGTH);
						if ( ret < 0 ) {
							perror("Error writing data");
							continue;
						}
					}
					// increment pointer by number of bytes for netflow record
					nf_record = (void *)((pointer_addr_t)nf_record + NETFLOW_V5_RECORD_LENGTH);
				}
			} // if cnt 
		} // for j
	} // while

	for ( j=0; j < num_profiles; j++ ) {
		profiles[j].first_seen = first_seen;
		profiles[j].last_seen = last_seen;
	}

	free((void *)record_buffer);

} // End of process_data


int main( int argc, char **argv ) {
unsigned int		num_profiles, quiet;
struct stat stat_buf;
char c, *rfile, *ffile, *filename, *p, *tstring, *profiledir, *subdir;
int syntax_only;
time_t t_start, t_end;

	tstring = NULL;
	profiledir = subdir = NULL;
	t_start = t_end = 0;
	syntax_only	    = 0;
	quiet			= 0;

	// default file names
	ffile = "filter.txt";
	rfile = "nfcapd";
	while ((c = getopt(argc, argv, "p:s:hf:r:Zt:Vq")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'Z':
				syntax_only = 1;
				break;
			case 'p':
				profiledir = optarg;
				break;
			case 's':
				subdir = optarg;
				break;
			case 'V':
				printf("%s: Version: %s %s\n%s\n",argv[0], nfdump_version, nfdump_date, rcsid);
				exit(0);
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
			case 'q':
				quiet = 1;
				break;
			default:
				usage(argv[0]);
				exit(0);
		}
	}


	if ( !profiledir ) {
		fprintf(stderr, "Profile directory required!\n");
		exit(255);
	}

	SetLimits(0,NULL, NULL);

	if ( stat(profiledir, &stat_buf) || !S_ISDIR(stat_buf.st_mode) ) {
		fprintf(stderr, "'%s' not a directory\n", profiledir);
		exit(255);
	}

	p = strrchr(rfile, '/');
	filename = p == NULL ? rfile : ++p;

	if ( strlen(filename) == 0 ) {
		fprintf(stderr, "Filename error");
		exit(254);
	}

	num_profiles = InitProfiles(profiledir, subdir, ffile, filename, syntax_only, quiet);
	if ( !num_profiles ) 
		exit(254);

	if ( syntax_only )
		exit(0);

	SetupInputFileSequence(NULL,rfile, NULL);

	if ( tstring ) {
		if ( !ScanTimeFrame(tstring, &t_start, &t_end) )
			exit(255);
	}

	process_data(GetProfiles(), num_profiles, t_start, t_end);

	CloseProfiles();

	return 0;
}
