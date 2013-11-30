/*
 *  This file is part of the nfdump project.
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
 *  $Id: nffile.c 70 2006-05-17 08:38:01Z peter $
 *
 *  $LastChangedRevision: 70 $
 *	
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"

const uint16_t MAGIC   = 0xA50C;
const uint16_t VERSION = 1;

char 	*CurrentIdent;

/* local vars */
static file_header_t	FileHeader;
static stat_record_t	NetflowStat;

#define ERR_SIZE 256
static char	error_string[ERR_SIZE];

#ifdef COMPAT14
int			Format14;
uint32_t	tstamp;

static void Compat14_ReadStat(char *sfile);
#endif

#if ( SIZEOF_VOID_P == 8 )
typedef uint64_t    pointer_addr_t;
#else
typedef uint32_t    pointer_addr_t;
#endif

/* function prototypes */

static void ZeroStat(void);


/* function definitions */

static void ZeroStat() {

	FileHeader.NumBlocks 	= 0;
	strncpy(FileHeader.ident, IdentNone, IdentLen);

	NetflowStat.first_seen  = 0;
	NetflowStat.last_seen	= 0;
	NetflowStat.msec_first	= 0;
	NetflowStat.msec_last	= 0;

	CurrentIdent			= FileHeader.ident;

} // End of ZeroStat

char *GetIdent(void) {

	return CurrentIdent;

} // End of GetIdent


int OpenFile(char *filename, stat_record_t **stat_record, char **err){
struct stat stat_buf;
int fd;

	*err = NULL;
	if ( stat_record ) 
		*stat_record = &NetflowStat;

	if ( filename == NULL ) {
		// stdin
		ZeroStat();
		fd = STDIN_FILENO;
	} else {
		// regular file
		if ( stat(filename, &stat_buf) ) {
			snprintf(error_string, ERR_SIZE, "Can't stat '%s': %s\n", filename, strerror(errno));
			error_string[ERR_SIZE-1] = 0;
			*err = error_string;
			ZeroStat();
			return -1;
		}

		if (!S_ISREG(stat_buf.st_mode) ) {
			snprintf(error_string, ERR_SIZE, "'%s' is not a file\n", filename);
			error_string[ERR_SIZE-1] = 0;
			*err = error_string;
			ZeroStat();
			return -1;
		}

		// printf("Statfile %s\n",filename);
		fd =  open(filename, O_RDONLY);
		if ( fd < 0 ) {
			snprintf(error_string, ERR_SIZE, "Error open file: %s\n", strerror(errno));
			error_string[ERR_SIZE-1] = 0;
			*err = error_string;
			ZeroStat();
			return fd;
		}

	}

#ifdef COMPAT14
	Format14 = 0;
#endif
	read(fd, (void *)&FileHeader, sizeof(FileHeader));
	if ( FileHeader.magic != MAGIC ) {
#ifdef COMPAT14
		if ( FileHeader.magic == 5 ) {
			Format14 = 1;
			lseek(fd, 0, SEEK_SET);

			FileHeader.magic 	 = MAGIC;
			FileHeader.version 	 = 0;
			FileHeader.flags	 = 0;
			FileHeader.NumBlocks = 0;
			Compat14_ReadStat(filename);
			CurrentIdent		= FileHeader.ident;
			return fd;
		}
#endif
		snprintf(error_string, ERR_SIZE, "Open file: bad magic: 0x%X\n", FileHeader.magic );
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		ZeroStat();
		close(fd);
		return -1;
	}
	if ( FileHeader.version != VERSION ) {
		snprintf(error_string, ERR_SIZE,"Open file: bad version: %u\n", FileHeader.version );
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		ZeroStat();
		close(fd);
		return -1;
	}
	read(fd, (void *)&NetflowStat, sizeof(NetflowStat));

// for debugging:
/*
	printf("Magic: 0x%X\n", FileHeader.magic);
	printf("Version: %i\n", FileHeader.version);
	printf("Flags: %i\n", FileHeader.flags);
	printf("NumBlocks: %i\n", FileHeader.NumBlocks);
	printf("Ident: %s\n\n", FileHeader.ident);

	printf("Flows: %llu\n", NetflowStat.numflows);
	printf("Flows_tcp: %llu\n", NetflowStat.numflows_tcp);
	printf("Flows_udp: %llu\n", NetflowStat.numflows_udp);
	printf("Flows_icmp: %llu\n", NetflowStat.numflows_icmp);
	printf("Flows_other: %llu\n", NetflowStat.numflows_other);
	printf("Packets: %llu\n", NetflowStat.numpackets);
	printf("Packets_tcp: %llu\n", NetflowStat.numpackets_tcp);
	printf("Packets_udp: %llu\n", NetflowStat.numpackets_udp);
	printf("Packets_icmp: %llu\n", NetflowStat.numpackets_icmp);
	printf("Packets_other: %llu\n", NetflowStat.numpackets_other);
	printf("Bytes: %llu\n", NetflowStat.numbytes);
	printf("Bytes_tcp: %llu\n", NetflowStat.numbytes_tcp);
	printf("Bytes_udp: %llu\n", NetflowStat.numbytes_udp);
	printf("Bytes_icmp: %llu\n", NetflowStat.numbytes_icmp);
	printf("Bytes_other: %llu\n", NetflowStat.numbytes_other);
	printf("First: %u\n", NetflowStat.first_seen);
	printf("Last: %u\n", NetflowStat.last_seen);
	printf("msec_first: %u\n", NetflowStat.msec_first);
	printf("msec_last: %u\n", NetflowStat.msec_last);
*/
	CurrentIdent		= FileHeader.ident;
	return fd;

} // End of OpenFile

void PrintStat(stat_record_t *s) {

	if ( s == NULL )
		s = &NetflowStat;

#ifdef COMPAT14
	if ( Format14 )
		printf("Time: %u\n", tstamp);
#endif
	printf("Ident: %s\n", FileHeader.ident);
	printf("Flows: %llu\n", s->numflows);
	printf("Flows_tcp: %llu\n", s->numflows_tcp);
	printf("Flows_udp: %llu\n", s->numflows_udp);
	printf("Flows_icmp: %llu\n", s->numflows_icmp);
	printf("Flows_other: %llu\n", s->numflows_other);
	printf("Packets: %llu\n", s->numpackets);
	printf("Packets_tcp: %llu\n", s->numpackets_tcp);
	printf("Packets_udp: %llu\n", s->numpackets_udp);
	printf("Packets_icmp: %llu\n", s->numpackets_icmp);
	printf("Packets_other: %llu\n", s->numpackets_other);
	printf("Bytes: %llu\n", s->numbytes);
	printf("Bytes_tcp: %llu\n", s->numbytes_tcp);
	printf("Bytes_udp: %llu\n", s->numbytes_udp);
	printf("Bytes_icmp: %llu\n", s->numbytes_icmp);
	printf("Bytes_other: %llu\n", s->numbytes_other);
	printf("First: %u\n", s->first_seen);
	printf("Last: %u\n", s->last_seen);
#ifdef COMPAT14
	if ( !Format14 ) {
#endif
		printf("msec_first: %u\n", s->msec_first);
		printf("msec_last: %u\n", s->msec_last);
		printf("Sequence failures: %u\n", s->sequence_failure);
#ifdef COMPAT14
	}
#endif
} // End of PrintStat

int OpenNewFile(char *filename, char **err) {
file_header_t	*file_header;
size_t			len;
int				nffd;

	*err = NULL;
	nffd = open(filename, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
	if ( nffd < 0 ) {
		return -1;
	}

	len = sizeof(file_header_t) + sizeof(stat_record_t);
	file_header = (file_header_t *)malloc(len);
	memset((void *)file_header, 0, len);

	/* magic set, version = 0 and flags = 0 => file open for writing */
	file_header->magic = MAGIC;
	if ( write(nffd, (void *)file_header, len) < len ) {
		snprintf(error_string, ERR_SIZE, "Failed to write file header: '%s'" , strerror(errno));
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		close(nffd);
		return -1;
	}

	return nffd;

} /* End of OpenNewFile */

void CloseUpdateFile(int fd, stat_record_t *stat_record, uint32_t record_count, char *ident, char **err ) {
file_header_t	file_header;

	*err = NULL;

	file_header.magic 		= MAGIC;
	file_header.version		= VERSION;
	file_header.flags		= 0;
	file_header.NumBlocks	= record_count;
	strncpy(file_header.ident, ident, IdentLen);
	file_header.ident[IdentLen - 1] = 0;

	if ( lseek(fd, 0, SEEK_SET) < 0 ) {
		snprintf(error_string, ERR_SIZE,"lseek failed: '%s'\n" , strerror(errno));
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		close(fd);
		return;
	}

	write(fd, (void *)&file_header, sizeof(file_header_t));
	write(fd, (void *)stat_record, sizeof(stat_record_t));
	if ( close(fd) < 0 ) {
		snprintf(error_string, ERR_SIZE,"close failed: '%s'" , strerror(errno));
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
	}
	
	close(fd);
	return;

} /* End of CloseUpdateFile */

/*
 * Expand file record into master record for further processing
 * LP64 CPUs need special 32bit operations as it is not guarateed, that 64bit
 * values are aligned 
 */
inline void ExpandRecord(common_record_t *input_record,master_record_t *output_record ) {
uint32_t	*u;
size_t		size;
void		*p = (void *)input_record;

	// Copy common data block
	size = sizeof(common_record_t) - sizeof(uint8_t[4]);
	memcpy((void *)output_record, p, size);
	p = (void *)input_record->data;

	output_record->fill = 0;

	if ( (input_record->flags & FLAG_IPV6_ADDR) != 0 )	{ // IPv6
		// IPv6
		memcpy((void *)output_record->v6.srcaddr, p, sizeof(ipv6_block_t));	
		p = (void *)((pointer_addr_t)p + sizeof(ipv6_block_t));
	} else { 	
		// IPv4
		u = (uint32_t *)p;
		output_record->v6.srcaddr[0] = 0;
		output_record->v6.srcaddr[1] = 0;
		output_record->v4.srcaddr 	 = u[0];

		output_record->v6.dstaddr[0] = 0;
		output_record->v6.dstaddr[1] = 0;
		output_record->v4.dstaddr 	 = u[1];
		p = (void *)((pointer_addr_t)p + 2 * sizeof(uint32_t));
	}

	// packet counter
	if ( (input_record->flags & FLAG_PKG_64 ) != 0 ) { 
		// 64bit packet counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val32[0] = v->val.val32[0];
		l.val.val32[1] = v->val.val32[1];
		output_record->dPkts = l.val.val64;
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit packet counter
		output_record->dPkts = *((uint32_t *)p);
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

	// byte counter
	if ( (input_record->flags & FLAG_BYTES_64 ) != 0 ) { 
		// 64bit byte counter
		value64_t	l, *v = (value64_t *)p;
		l.val.val32[0] = v->val.val32[0];
		l.val.val32[1] = v->val.val32[1];
		output_record->dOctets = l.val.val64;
		p = (void *)((pointer_addr_t)p + sizeof(uint64_t));
	} else {	
		// 32bit bytes counter
		output_record->dOctets = *((uint32_t *)p);
		p = (void *)((pointer_addr_t)p + sizeof(uint32_t));
	}

} // End of ExpandRecord

#ifdef COMPAT14

/*
 * Everything below is code to read nfdump <= v1.4 binary data files.
 * This code will be removed in furture
 */

#ifdef __SUNPRO_C
extern 
#endif
inline ssize_t	Compat14_ReadHeader(int fd, data_block_header_t *flow_header) {
compat14_flow_header_t	compat14_header;
ssize_t	num;

	num = read(fd, (void *)&compat14_header, sizeof(compat14_flow_header_t));
	if ( num <= 0 ) {
		flow_header->NumBlocks 	= 0;
		flow_header->size 		= 0;
		flow_header->id 		= DATA_BLOCK_TYPE_1;
		flow_header->pad 		= 0;
		return num;
	}

	flow_header->NumBlocks 	= compat14_header.count;
	flow_header->size 		= compat14_header.count * sizeof(comapt14_flow_record_t);
	flow_header->id 		= DATA_BLOCK_TYPE_1;
	flow_header->pad 		= 0;

	return num;

} // End of Compat14_ReadHeader

#ifdef __SUNPRO_C
extern 
#endif
inline ssize_t Compat14_ReadRecords(int fd, void *buffer, data_block_header_t *flow_header) {
comapt14_flow_record_t	compat14_records[30];
common_record_t		*record_buffer;
uint32_t			*val, record_size;

ssize_t	num;
int i;

	record_buffer = (common_record_t *)buffer;
	val			  = (uint32_t *)record_buffer->data;
	record_size	  = (pointer_addr_t)&val[4] - (pointer_addr_t)buffer;

	if ( flow_header->NumBlocks > 30 || flow_header->NumBlocks == 0 )
		return 0;

	num = read(fd, (void *)compat14_records, flow_header->NumBlocks * sizeof(comapt14_flow_record_t));
	if ( num <= 0 )
		return num;

	if ( num != flow_header->NumBlocks * sizeof(comapt14_flow_record_t) ) 
		return -1;

	for ( i=0; i<flow_header->NumBlocks; i++ ) {
		record_buffer->flags		= 0;
		record_buffer->size			= record_size;
		record_buffer->mark			= 0;
		record_buffer->first		= compat14_records[i].First;
		record_buffer->last			= compat14_records[i].Last;
		record_buffer->msec_first	= compat14_records[i].msec_first;
		record_buffer->msec_last	= compat14_records[i].msec_last;

		record_buffer->dir			= 0;
		record_buffer->tcp_flags	= compat14_records[i].tcp_flags;
		record_buffer->prot			= compat14_records[i].prot;
		record_buffer->tos			= compat14_records[i].tos;
		record_buffer->input		= compat14_records[i].input;
		record_buffer->output		= compat14_records[i].output;
		record_buffer->srcas		= compat14_records[i].src_as;
		record_buffer->dstas		= compat14_records[i].dst_as;
		record_buffer->srcport		= compat14_records[i].srcport;
		record_buffer->dstport		= compat14_records[i].dstport;

		val[0] = compat14_records[i].srcaddr;
		val[1] = compat14_records[i].dstaddr;
		val[2] = compat14_records[i].dPkts;
		val[3] = compat14_records[i].dOctets;

		record_buffer = (common_record_t *)((pointer_addr_t)record_buffer + record_size);
		val			  = (uint32_t *)record_buffer->data;
	}
	return num;

} // End of Compat14_ReadRecords

static void Compat14_ReadStat(char *sfile){
FILE *fd;
char	stat_filename[256];

	ZeroStat();
    if ( sfile == NULL )
		return;

	strncpy(stat_filename, sfile, 256);
	sfile[255] = 0;
	strncat(stat_filename, ".stat", 256);
	sfile[255] = 0;

    fd = fopen(stat_filename, "r");
    if ( !fd ) {
        return;
    }

    fscanf(fd, "Time: %u\n", &tstamp);
    fscanf(fd, "Ident: %s\n", FileHeader.ident); 
    fscanf(fd, "Flows: %llu\n", &NetflowStat.numflows);
    fscanf(fd, "Flows_tcp: %llu\n", &NetflowStat.numflows_tcp);
    fscanf(fd, "Flows_udp: %llu\n", &NetflowStat.numflows_udp);
    fscanf(fd, "Flows_icmp: %llu\n", &NetflowStat.numflows_icmp);
    fscanf(fd, "Flows_other: %llu\n", &NetflowStat.numflows_other);
    fscanf(fd, "Packets: %llu\n", &NetflowStat.numpackets);
    fscanf(fd, "Packets_tcp: %llu\n", &NetflowStat.numpackets_tcp);
    fscanf(fd, "Packets_udp: %llu\n", &NetflowStat.numpackets_udp);
    fscanf(fd, "Packets_icmp: %llu\n", &NetflowStat.numpackets_icmp);
    fscanf(fd, "Packets_other: %llu\n", &NetflowStat.numpackets_other);
    fscanf(fd, "Bytes: %llu\n", &NetflowStat.numbytes);
    fscanf(fd, "Bytes_tcp: %llu\n", &NetflowStat.numbytes_tcp);
    fscanf(fd, "Bytes_udp: %llu\n", &NetflowStat.numbytes_udp);
    fscanf(fd, "Bytes_icmp: %llu\n", &NetflowStat.numbytes_icmp);
    fscanf(fd, "Bytes_other: %llu\n", &NetflowStat.numbytes_other);
    fscanf(fd, "First: %u\n", &NetflowStat.first_seen);
    fscanf(fd, "Last: %u\n", &NetflowStat.last_seen);
	NetflowStat.msec_first = 0;
	NetflowStat.msec_last  = 0;
	NetflowStat.sequence_failure = 0;

    fclose(fd);

} // End of Compat14_ReadStat

#endif

