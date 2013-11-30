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
 *  $Author: haag $
 *
 *  $Id: nfreader.c 9 2009-05-07 08:59:31Z haag $
 *
 *  $LastChangedRevision: 9 $
 *	
 *
 */

/* 
 * nfreader is sample code for reading nfdump binary files.
 * It accepts the standard nfdump file select options -r, -M and -R
 * Therefore it allows you to loop over multiple files and process the netflow record.
 *
 * Insert your code in the process_data function after the call to ExpandRecord
 * To build the binary: first compile nfdump as usual.
 * Then compile nfreader:
 *
 * make nfreader
 *
 * This compiles this code and links the required nfdump files
 * If you do it by hand:
 *
 * gcc -c nfreader.c
 * gcc -o nfreader nfreader.o nffile.o flist.o util.o  
 *
 */
 
#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "rbtree.h"
#include "nftree.h"
#include "nffile.h"
#include "util.h"
#include "flist.h"

#define BUFFSIZE 1048576
#define MAX_BUFFER_SIZE 104857600

#if ( SIZEOF_VOID_P == 8 )
typedef uint64_t    pointer_addr_t;
#else
typedef uint32_t    pointer_addr_t;
#endif

/* Global Variables */
FilterEngine_data_t *Engine;

/* exported fuctions */
void LogError(char *format, ...);

/* Function Prototypes */
static void usage(char *name);

static void print_record(void *record, char *s );

static void process_data(void);

/* Functions */

static void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tthis text you see right here\n"
					"-r\t\tread input from file\n"
					"-M <expr>\tRead input from multiple directories.\n"
					"-R <expr>\tRead input from sequence of files.\n"
					, name);
} /* usage */

/* 
 * some modules are needed for daemon code as well as normal stdio code 
 * therefore a generic LogError is defined, which maps in this case
 * to stderr
 */
void LogError(char *format, ...) {
va_list var_args;

	va_start(var_args, format);
	vfprintf(stderr, format, var_args);
	va_end(var_args);

} // End of LogError

static void print_record(void *record, char *s ) {
char 		as[40], ds[40], datestr1[64], datestr2[64];
time_t		when;
struct tm 	*ts;
master_record_t *r = (master_record_t *)record;

	if ( (r->flags & FLAG_IPV6_ADDR ) != 0 ) { // IPv6
		r->v6.srcaddr[0] = htonll(r->v6.srcaddr[0]);
		r->v6.srcaddr[1] = htonll(r->v6.srcaddr[1]);
		r->v6.dstaddr[0] = htonll(r->v6.dstaddr[0]);
		r->v6.dstaddr[1] = htonll(r->v6.dstaddr[1]);
		inet_ntop(AF_INET6, r->v6.srcaddr, as, sizeof(as));
		inet_ntop(AF_INET6, r->v6.dstaddr, ds, sizeof(ds));
	} else {	// IPv4
		r->v4.srcaddr = htonl(r->v4.srcaddr);
		r->v4.dstaddr = htonl(r->v4.dstaddr);
		inet_ntop(AF_INET, &r->v4.srcaddr, as, sizeof(as));
		inet_ntop(AF_INET, &r->v4.dstaddr, ds, sizeof(ds));
	}
	as[40-1] = 0;
	ds[40-1] = 0;

	when = r->first;
	ts = localtime(&when);
	strftime(datestr1, 63, "%Y-%m-%d %H:%M:%S", ts);

	when = r->last;
	ts = localtime(&when);
	strftime(datestr2, 63, "%Y-%m-%d %H:%M:%S", ts);

	snprintf(s, 1023, "\n"
"Flow Record: \n"
"  srcaddr     = %16s\n"
"  dstaddr     = %16s\n"
"  first       =       %10u [%s]\n"
"  last        =       %10u [%s]\n"
"  msec_first  =            %5u\n"
"  msec_last   =            %5u\n"
"  prot        =              %3u\n"
"  srcport     =            %5u\n"
"  dstport     =            %5u\n"
"  dPkts       =       %10llu\n"
"  dOctets     =       %10llu\n"
, 
		as, ds, r->first, datestr1, r->last, datestr2, r->msec_first, r->msec_last, 
		r->prot, r->srcport, r->dstport,
		(unsigned long long)r->dPkts, (unsigned long long)r->dOctets);

	s[1024-1] = 0;

} // End of print_record


static void process_data(void) {
data_block_header_t block_header;
common_record_t *flow_record, *in_buff;
master_record_t master_record;
uint32_t		buffer_size;
int 			i, rfd, done, ret;
char			*string;

	// Get the first file handle
	rfd = GetNextFile(0, 0, 0, NULL);
	if ( rfd < 0 ) {
		if ( rfd == FILE_ERROR )
			perror("Can't open input file for reading");
		return;
	}

	// allocate buffer suitable for netflow version
	buffer_size = BUFFSIZE;
	in_buff = (common_record_t *) malloc(buffer_size);

	if ( !in_buff ) {
		perror("Memory allocation error");
		close(rfd);
		return;
	}

    // setup Filter Engine to point to master_record, as any record read from file
    // is expanded into this record
    Engine->nfrecord = (uint64_t *)&master_record;

	done = 0;
	while ( !done ) {
		// get next data block from file
		ret = ReadBlock(rfd, &block_header, (void *)in_buff, &string);

		switch (ret) {
			case NF_CORRUPT:
			case NF_ERROR:
				if ( ret == NF_CORRUPT ) 
					fprintf(stderr, "Skip corrupt data file '%s': '%s'\n",GetCurrentFilename(), string);
				else 
					fprintf(stderr, "Read error in file '%s': %s\n",GetCurrentFilename(), strerror(errno) );
				// fall through - get next file in chain
			case NF_EOF:
				rfd = GetNextFile(rfd, 0, 0, NULL);
				if ( rfd < 0 ) {
					if ( rfd == NF_ERROR )
						fprintf(stderr, "Read error in file '%s': %s\n",GetCurrentFilename(), strerror(errno) );

					// rfd == EMPTY_LIST
					done = 1;
				} // else continue with next file
				continue;
	
				break; // not really needed
		}

		if ( block_header.id != DATA_BLOCK_TYPE_1 ) {
			fprintf(stderr, "Can't process block type %u. Skip block.\n", block_header.id);
			continue;
		}

		flow_record = in_buff;
		for ( i=0; i < block_header.NumBlocks; i++ ) {
			char	string[1024];
			int		match;

			ExpandRecord( flow_record, &master_record);

			match = (*Engine->FilterEngine)(Engine);

			if ( match ) {

					/* 
			 		* insert hier your calls to your processing routine 
			 		* master_record now contains the next flow record as specified in nffile.c
			 		* for example you can print each record:
			 		*
			 		*/

					print_record(&master_record, string);
					printf("%s\n", string);
			}

			// Advance pointer by number of bytes for netflow record
			flow_record = (common_record_t *)((pointer_addr_t)flow_record + flow_record->size);	

		} // for all records

	} // while

	if ( rfd > 0 ) 
		close(rfd);

	free((void *)in_buff);

} // End of process_data


int main( int argc, char **argv ) {
char 		*rfile, *Rfile, *Mdirs, *filter;
int			c;

	// filter = "proto UDP and not ( port 53 or port 123 ) and packets = 1 and bpp < 120";
	filter = "any";
	rfile = Rfile = Mdirs = NULL;
	while ((c = getopt(argc, argv, "r:M:R:")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'r':
				rfile = optarg;
				if ( strcmp(rfile, "-") == 0 )
					rfile = NULL;
				break;
			case 'M':
				Mdirs = optarg;
				break;
			case 'R':
				Rfile = optarg;
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
//        filter = argv[optind];
    }

    Engine = CompileFilter(filter);
    if ( !Engine )
        exit(254);

	if ( rfile && Rfile ) {
		fprintf(stderr, "-r and -R are mutually exclusive. Plase specify either -r or -R\n");
		exit(255);
	}
	if ( Mdirs && !(rfile || Rfile) ) {
		fprintf(stderr, "-M needs either -r or -R to specify the file or file list. Add '-R .' for all files in the directories.\n");
		exit(255);
	}

	SetupInputFileSequence(Mdirs, rfile, Rfile);

	process_data();

	return 0;
}
