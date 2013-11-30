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
 *  $Author: haag $
 *
 *  $Id: ft2nfdump.c 9 2009-05-07 08:59:31Z haag $
 *
 *  $LastChangedRevision: 9 $
 *	
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <ftlib.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "version.h"
#include "nf_common.h"
#include "nffile.h"
#include "launch.h"

#include "ftbuild.h"

/* Global defines */
#define MAXRECORDS 30

/* Global consts */

#define HIGHWATER BUFFSIZE * 0.9

extern uint16_t MAGIC;
extern uint16_t VERSION;

static char const *vers_id = "$Id: ft2nfdump.c 9 2009-05-07 08:59:31Z haag $";

typedef struct v5_block_s {
	uint32_t	srcaddr;
	uint32_t	dstaddr;
	uint32_t	dPkts;
	uint32_t	dOctets;
	uint8_t		data[4];	// link to next record
} v5_block_t;

/* prototypes */
void usage(char *name);

void LogError(char *format, ...);

int flows2nfdump(struct ftio *ftio, int extended, uint32_t limitflows);

void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tthis text you see right here.\n"
					"-E\t\tDump records in ASCII extended format to stdout.\n"
					"-c\t\tLimit number of records to convert.\n"
					"-V\t\tPrint version and exit.\n"
					"-r\t\tread input from file\n"
					"Convert flow-tools format to nfdump format:\n"
					"ft2nfdump -r <flow-tools-data-file> | nfdump -w <nfdump-file>\n"
				, name);

} // End of usage

/* 
 * some code is needed for daemon code as well as normal stdio code 
 * therefore a generic LogError is defined, which maps in this case
 * to stderr
 */
void LogError(char *format, ...) {
va_list var_args;

	va_start(var_args, format);
	vfprintf(stderr, format, var_args);
	va_end(var_args);

} // End of LogError

int flows2nfdump(struct ftio *ftio, int extended, uint32_t limitflows) {
struct fttime ftt;
struct fts3rec_offsets fo;
struct ftver ftv;
data_block_header_t *nf_header;
file_header_t		*file_header;
common_record_t 	*record_buff, *nf_record;
v5_block_t			*v5_block;
char 				*rec, *string;
uint32_t			when, unix_secs, unix_nsecs, sysUpTime, cnt, output_record_length;
void				*flow_buff;
size_t				len;

	/* setup memory buffer */
	flow_buff = malloc(BUFFSIZE);
	if ( !flow_buff ) {
    	fterr_errx(1, "Buffer allocation error: %s.", strerror(errno));
	}
	nf_header 	= (data_block_header_t *)flow_buff;
	record_buff = (common_record_t *)((pointer_addr_t)flow_buff + sizeof(data_block_header_t));
	
	output_record_length = sizeof(common_record_t) + sizeof(v5_block_t) - 2 * sizeof(uint8_t[4]);

	/* Init defaults in header */
	nf_header->NumBlocks 		= 0;
	nf_header->size 			= 0;
	nf_header->id 				= DATA_BLOCK_TYPE_1;
	nf_header->pad				= 0;

	if (ftio_check_xfield(ftio, FT_XFIELD_DPKTS |
		FT_XFIELD_DOCTETS | FT_XFIELD_FIRST | FT_XFIELD_LAST | FT_XFIELD_INPUT |
		FT_XFIELD_OUTPUT | FT_XFIELD_SRCADDR | FT_XFIELD_DSTADDR |
		FT_XFIELD_SRCPORT | FT_XFIELD_DSTPORT | FT_XFIELD_SRC_AS | FT_XFIELD_DST_AS |
		FT_XFIELD_UNIX_SECS | FT_XFIELD_UNIX_NSECS | FT_XFIELD_SYSUPTIME |
		FT_XFIELD_TOS | FT_XFIELD_TCP_FLAGS | FT_XFIELD_PROT)) {
		fterr_warnx("Flow record missing required field for format.");
		return -1;
	}

	// initialize file header and dummy stat record
	len = sizeof(file_header_t) + sizeof(stat_record_t);
	file_header = (file_header_t *)malloc(len);
	memset((void *)file_header, 0, len);
	file_header->magic 		= MAGIC;
	file_header->version 	= VERSION;
	strncpy(file_header->ident, "none", IDENT_SIZE);
	write(STDOUT_FILENO, (void *)file_header, len) ;

	cnt = 0;
	ftio_get_ver(ftio, &ftv);
	fts3rec_compute_offsets(&fo, &ftv);

	nf_record = record_buff;
	v5_block  = (v5_block_t *)nf_record->data;
	while ((rec = ftio_read(ftio))) {

		nf_record->flags		= 0;
		nf_record->mark			= 0;
		nf_record->size			= output_record_length;
	
		unix_secs  = *((u_int32*)(rec+fo.unix_secs));
		unix_nsecs = *((u_int32*)(rec+fo.unix_nsecs));
		sysUpTime  = *((u_int32*)(rec+fo.sysUpTime));

		when	   = *((u_int32*)(rec+fo.First));
    	ftt = ftltime(sysUpTime, unix_secs, unix_nsecs, when);
		nf_record->first 		= ftt.secs;
		nf_record->msec_first 	= ftt.msecs;
	
		when	   = *((u_int32*)(rec+fo.Last));
    	ftt = ftltime(sysUpTime, unix_secs, unix_nsecs, when);
		nf_record->last 		= ftt.secs;
		nf_record->msec_last 	= ftt.msecs;
	
		nf_record->input 		= *((u_int16*)(rec+fo.input));
		nf_record->output 		= *((u_int16*)(rec+fo.output));
		nf_record->srcport 		= *((u_int16*)(rec+fo.srcport));
		nf_record->dstport 		= *((u_int16*)(rec+fo.dstport));
		nf_record->prot 		= *((u_int8*)(rec+fo.prot));
		nf_record->tcp_flags	= *((u_int8*)(rec+fo.tcp_flags));
		nf_record->tos 			= *((u_int8*)(rec+fo.tos));
		nf_record->srcas 		= *((u_int16*)(rec+fo.src_as));
		nf_record->dstas 		= *((u_int16*)(rec+fo.dst_as));

		v5_block->srcaddr 		= *((u_int32*)(rec+fo.srcaddr));
		v5_block->dstaddr 		= *((u_int32*)(rec+fo.dstaddr));
		v5_block->dOctets 		= *((u_int32*)(rec+fo.dOctets));
		v5_block->dPkts 		= *((u_int32*)(rec+fo.dPkts));
	
		nf_header->NumBlocks++;
		nf_header->size 		+= output_record_length;

		if ( extended ) {
			master_record_t	print_record;
			size_t size = sizeof(common_record_t) - sizeof(uint8_t[4]);
			memcpy((void *)&print_record, (void *)nf_record, size);
			print_record.v6.srcaddr[0] = 0;
			print_record.v6.srcaddr[1] = 0;
			print_record.v6.dstaddr[0] = 0;
			print_record.v6.dstaddr[1] = 0;
			print_record.v4.srcaddr = v5_block->srcaddr;
			print_record.v4.dstaddr = v5_block->dstaddr;
			print_record.dPkts		= v5_block->dPkts;
			print_record.dOctets	= v5_block->dOctets;

			format_file_block_record(&print_record, 1, &string, 0, 0);
			printf("%s\n", string);
		} 

		if ( nf_header->size >= HIGHWATER ) {
			if ( !extended ) {
				write(STDOUT_FILENO, flow_buff, sizeof(data_block_header_t) + nf_header->size);
			}
			nf_header->NumBlocks	= 0;
			nf_header->size 		= 0;
			nf_record 				= record_buff;
			v5_block  				= (v5_block_t *)nf_record->data;
		} else {
			nf_record = (common_record_t *)((pointer_addr_t)nf_record + output_record_length);
			v5_block  = (v5_block_t *)nf_record->data;
		}
		cnt++;
		if ( cnt == limitflows )
			break;

	} /* while */

	// write the last records in buffer
	if ( !extended && nf_header->size ) {
		write(STDOUT_FILENO, flow_buff, sizeof(data_block_header_t) + nf_header->size);
	}

	free(flow_buff);

	return 0;

} // End of flows2nfdump

int main(int argc, char **argv) {
struct ftio ftio;
struct stat statbuf;
uint32_t	limitflows;
int i, extended, ret, fd;
char   *ftfile;

	/* init fterr */
	fterr_setid(argv[0]);

	extended 	= 0;
	limitflows 	= 0;
	ftfile   	= NULL;

	while ((i = getopt(argc, argv, "EVc:hr:?")) != -1)
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
		
			case 'c':	
				limitflows = atoi(optarg);
				if ( !limitflows ) {
					fprintf(stderr, "Option -c needs a number > 0\n");
					exit(255);
				}
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
	
	ret = flows2nfdump(&ftio, extended, limitflows);

	return ret;

} // End of main

