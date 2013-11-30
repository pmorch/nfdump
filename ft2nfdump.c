/*
 *  Copyright (c) 2001 Mark Fullmer and The Ohio State University
 *  All rights reserved.

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
 *  Flow-Tools related code taken from flow-tools-0.67 cretated by Mark Fullmer
 *
 *  $Author: peter $
 *
 *  $Id: ft2nfdump.c 53 2005-11-17 07:45:34Z peter $
 *
 *  $LastChangedRevision: 53 $
 *	
 *
 */

#include <ftlib.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>

#include <string.h>
#include <errno.h>
#include "ftbuild.h"

#include <sys/stat.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "version.h"
#include "nf_common.h"

/* Global defines */
#define MAXRECORDS 30

/* Global consts */
static int  const BUFFSIZE = sizeof(flow_header_t) + MAXRECORDS * sizeof(flow_record_t);
static char const *vers_id = "$Id: ft2nfdump.c 53 2005-11-17 07:45:34Z peter $";

/* prototypes */
void usage(char *name);

int flows2nfdump(struct ftio *ftio, int extended);

void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tthis text you see right here.\n"
					"-E\t\tDump records in ASCII extended format to stdout.\n"
					"-V\t\tPrint version and exit.\n"
					"-r\t\tread input from file\n"
					"Convert flow-tools format to nfdump format:\n"
					"ft2nfdump -r <flow-tools-data-file> | nfdump -w <nfdump-file>\n"
				, name);

} // End of usage

int flows2nfdump(struct ftio *ftio, int extended) {
struct fttime ftt;
struct fts3rec_offsets fo;
struct ftver ftv;
flow_header_t *nf_header;
flow_record_t *record_buff, *nf_record;
char 		*rec, *string;
uint32_t	when, unix_secs, unix_nsecs, sysUpTime;
int			rec_count;
void		*flow_buff;

	/* setup memory buffer */
	flow_buff = malloc(BUFFSIZE);
	if ( !flow_buff ) {
    	fterr_errx(1, "Buffer allocation error: %s.", strerror(errno));
	}
	nf_header 	= (flow_header_t *)flow_buff;
	record_buff = (flow_record_t *)(flow_buff + sizeof(flow_header_t));
	rec_count   = 0;
	
	/* Init defaults in header */
	nf_header->version 			= 5;
	nf_header->count 			= MAXRECORDS;
	nf_header->flow_sequence 	= 1;
	nf_header->engine_type 		= 0;
	nf_header->engine_id 		= 0;
	nf_header->layout_version 	= 1;

	if (ftio_check_xfield(ftio, FT_XFIELD_DPKTS |
		FT_XFIELD_DOCTETS | FT_XFIELD_FIRST | FT_XFIELD_LAST | FT_XFIELD_INPUT |
		FT_XFIELD_OUTPUT | FT_XFIELD_SRCADDR | FT_XFIELD_DSTADDR |
		FT_XFIELD_SRCPORT | FT_XFIELD_DSTPORT | FT_XFIELD_SRC_AS | FT_XFIELD_DST_AS |
		FT_XFIELD_UNIX_SECS | FT_XFIELD_UNIX_NSECS | FT_XFIELD_SYSUPTIME |
		FT_XFIELD_TOS | FT_XFIELD_TCP_FLAGS | FT_XFIELD_PROT)) {
		fterr_warnx("Flow record missing required field for format.");
		return -1;
	}

	ftio_get_ver(ftio, &ftv);
	fts3rec_compute_offsets(&fo, &ftv);

	while ((rec = ftio_read(ftio))) {
		nf_record = &record_buff[rec_count];

		nf_record->pad 			= 0;
		nf_record->nexthop		= 0;
	
		nf_record->dOctets 		= *((u_int32*)(rec+fo.dOctets));
		nf_record->dPkts 		= *((u_int32*)(rec+fo.dPkts));
	
		unix_secs  = *((u_int32*)(rec+fo.unix_secs));
		unix_nsecs = *((u_int32*)(rec+fo.unix_nsecs));
		sysUpTime  = *((u_int32*)(rec+fo.sysUpTime));

		when	   = *((u_int32*)(rec+fo.First));
    	ftt = ftltime(sysUpTime, unix_secs, unix_nsecs, when);
		nf_record->First 		= ftt.secs;
		nf_record->msec_first 	= ftt.msecs;
	
		when	   = *((u_int32*)(rec+fo.Last));
    	ftt = ftltime(sysUpTime, unix_secs, unix_nsecs, when);
		nf_record->Last 		= ftt.secs;
		nf_record->msec_last 	= ftt.msecs;
	
		nf_record->srcaddr 		= *((u_int32*)(rec+fo.srcaddr));
		nf_record->dstaddr 		= *((u_int32*)(rec+fo.dstaddr));
		nf_record->input 		= *((u_int16*)(rec+fo.input));
		nf_record->output 		= *((u_int16*)(rec+fo.output));
		nf_record->srcport 		= *((u_int16*)(rec+fo.srcport));
		nf_record->dstport 		= *((u_int16*)(rec+fo.dstport));
		nf_record->prot 		= *((u_int8*)(rec+fo.prot));
		nf_record->tcp_flags	= *((u_int8*)(rec+fo.tcp_flags));
		nf_record->tos 			= *((u_int8*)(rec+fo.tos));
		nf_record->src_as 		= *((u_int16*)(rec+fo.src_as));
		nf_record->dst_as 		= *((u_int16*)(rec+fo.dst_as));
	
		rec_count++;
		if ( rec_count == MAXRECORDS ) {
			rec_count = 0;
			if ( !extended ) {
				nf_header->flow_sequence += MAXRECORDS;
  				nf_header->SysUptime	 = *((u_int32*)(rec+fo.sysUpTime));
  				nf_header->unix_secs	 = *((u_int32*)(rec+fo.unix_secs));
  				nf_header->unix_nsecs	 = *((u_int32*)(rec+fo.unix_nsecs));
				write(STDOUT_FILENO, flow_buff, BUFFSIZE);
			}
		}

		if ( extended ) {
			flow_record_raw(nf_record, 0, 0, 0, &string, 0);
			printf("%s\n", string);
		} 


	} /* while */

	// write the last records in buffer
	if ( !extended && rec_count ) {
		nf_header->count 		  = rec_count;
		nf_header->flow_sequence += rec_count;
	 	write(STDOUT_FILENO, flow_buff, sizeof(flow_header_t) + rec_count * sizeof(flow_record_t));
	}
	free(flow_buff);

	return 0;

} // End of flows2nfdump

int main(int argc, char **argv) {
struct ftio ftio;
struct stat statbuf;
int i, extended, ret, fd;
char   *ftfile;

	/* init fterr */
	fterr_setid(argv[0]);

	extended = 0;
	ftfile   = NULL;

	while ((i = getopt(argc, argv, "EVhr:?")) != -1)
		switch (i) {
			case 'h': /* help */
				case '?':
				usage(argv[0]);
				exit (0);
				break;
		
			case 'V':
				printf("%s: Version: %s %s\n%s\n",argv[0], nfdump_version, nfdump_date, vers_id);
				exit(0);
				break;

			case 'E':
				extended = 1;
				break;
		
			case 'r':
				ftfile = optarg;
				if ( (stat(ftfile, &statbuf) < 0 ) || !(statbuf.st_mode & S_IFREG) ) {
					fprintf(stderr, "No such file: '%s'\n", ftfile);
					exit(255);
				}
				break;
		
			default:
				usage(argv[0]);
				exit (1);
				break;
	
		} /* switch */
	
	if (argc - optind)
	fterr_errx(1, "Extra arguments starting with %s.", argv[optind]);
	
	if ( ftfile ) {
		fd = open(ftfile, O_RDONLY, 0);
		if ( fd < 0 ) {
    		fprintf(stderr, "Can't open file '%s': %s.", ftfile, strerror(errno));
			exit(255);
		}
	} else {
		fd = 0;
	}

	/* read from fd */
	if (ftio_init(&ftio, fd, FT_IO_FLAG_READ) < 0)
		fterr_errx(1, "ftio_init(): failed");
	
	ret = flows2nfdump(&ftio, extended);

	return ret;

} // End of main

