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
 *  $Id: nffile.c 92 2007-08-24 12:10:24Z peter $
 *
 *  $LastChangedRevision: 92 $
 *	
 */

#include "config.h"

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

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

void SumStatRecords(stat_record_t *s1, stat_record_t *s2) {

	s1->numflows			+= s2->numflows;
	s1->numbytes			+= s2->numbytes;
	s1->numpackets			+= s2->numpackets;
	s1->numflows_tcp		+= s2->numflows_tcp;
	s1->numflows_udp		+= s2->numflows_udp;
	s1->numflows_icmp		+= s2->numflows_icmp;
	s1->numflows_other		+= s2->numflows_other;
	s1->numbytes_tcp		+= s2->numbytes_tcp;
	s1->numbytes_udp		+= s2->numbytes_udp;
	s1->numbytes_icmp		+= s2->numbytes_icmp;
	s1->numbytes_other		+= s2->numbytes_other;
	s1->numpackets_tcp		+= s2->numpackets_tcp;
	s1->numpackets_udp		+= s2->numpackets_udp;
	s1->numpackets_icmp		+= s2->numpackets_icmp;
	s1->numpackets_other	+= s2->numpackets_other;
	s1->sequence_failure	+= s2->sequence_failure;

	if ( s2->first_seen < s1->first_seen ) {
		s1->first_seen = s2->first_seen;
		s1->msec_first = s2->msec_first;
	}
	if ( s2->first_seen == s1->first_seen && 
		 s2->msec_first < s1->msec_first ) 
			s1->msec_first = s2->msec_first;

	if ( s2->last_seen > s1->last_seen ) {
		s1->last_seen = s2->last_seen;
		s1->msec_last = s2->msec_last;
	}
	if ( s2->last_seen == s1->last_seen && 
		 s2->msec_last > s1->msec_last ) 
			s1->msec_last = s2->msec_last;

} // End of AddStatRecords


char *GetIdent(void) {

	return CurrentIdent;

} // End of GetIdent


int OpenFile(char *filename, stat_record_t **stat_record, char **err){
struct stat stat_buf;
int fd, ret;

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
	ret = read(fd, (void *)&FileHeader, sizeof(FileHeader));
	if ( FileHeader.magic != MAGIC ) {
#ifdef COMPAT14
		// ret = 0 == EOF. This is an empty file
		if ( ret == 0 || FileHeader.magic == 5 ) {
			Format14 = 1;
			lseek(fd, 0, SEEK_SET);

			FileHeader.magic 	 = MAGIC;
			FileHeader.version 	 = VERSION;
			FileHeader.flags	 = 0;
			FileHeader.NumBlocks = 0;
			Compat14_ReadStat(filename);
			CurrentIdent		= FileHeader.ident;
			return fd;
		}
#endif
		snprintf(error_string, ERR_SIZE, "Open file '%s': bad magic: 0x%X\n", filename, FileHeader.magic );
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		ZeroStat();
		close(fd);
		return -1;
	}
	if ( FileHeader.version != VERSION ) {
		snprintf(error_string, ERR_SIZE,"Open file %s: bad version: %u\n", filename, FileHeader.version );
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

int ChangeIdent(char *filename, char *Ident, char **err) {
struct stat stat_buf;
int fd, ret;

	*err = NULL;
	if ( filename == NULL ) 
		return 0;

	if ( stat(filename, &stat_buf) ) {
		snprintf(error_string, ERR_SIZE, "Can't stat '%s': %s\n", filename, strerror(errno));
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		return -1;
	}

	if (!S_ISREG(stat_buf.st_mode) ) {
		snprintf(error_string, ERR_SIZE, "'%s' is not a file\n", filename);
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		return -1;
	}

	fd =  open(filename, O_RDWR);
	if ( fd < 0 ) {
		snprintf(error_string, ERR_SIZE, "Error open file: %s\n", strerror(errno));
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		return fd;
	}

	ret = read(fd, (void *)&FileHeader, sizeof(FileHeader));
	if ( FileHeader.magic != MAGIC ) {
		snprintf(error_string, ERR_SIZE, "Open file '%s': bad magic: 0x%X\n", filename, FileHeader.magic );
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		close(fd);
		return -1;
	}
	if ( FileHeader.version != VERSION ) {
		snprintf(error_string, ERR_SIZE,"Open file %s: bad version: %u\n", filename, FileHeader.version );
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		close(fd);
		return -1;
	}

	strncpy(FileHeader.ident, Ident, IdentLen);
	FileHeader.ident[IdentLen - 1] = 0;

	if ( lseek(fd, 0, SEEK_SET) < 0 ) {
		snprintf(error_string, ERR_SIZE,"lseek failed: '%s'\n" , strerror(errno));
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		close(fd);
		return -1;
	}

	write(fd, (void *)&FileHeader, sizeof(file_header_t));
	if ( close(fd) < 0 ) {
		snprintf(error_string, ERR_SIZE,"close failed: '%s'" , strerror(errno));
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
		return -1;
	}
	
	return 0;

} // End of ChangeIdent


void PrintStat(stat_record_t *s) {

	if ( s == NULL )
		s = &NetflowStat;

#ifdef COMPAT14
	if ( Format14 )
		printf("Time: %u\n", tstamp);
#endif
	// format info: make compiler happy with conversion to (unsigned long long), 
	// which does not change the size of the parameter
	printf("Ident: %s\n", FileHeader.ident);
	printf("Flows: %llu\n", (unsigned long long)s->numflows);
	printf("Flows_tcp: %llu\n", (unsigned long long)s->numflows_tcp);
	printf("Flows_udp: %llu\n", (unsigned long long)s->numflows_udp);
	printf("Flows_icmp: %llu\n", (unsigned long long)s->numflows_icmp);
	printf("Flows_other: %llu\n", (unsigned long long)s->numflows_other);
	printf("Packets: %llu\n", (unsigned long long)s->numpackets);
	printf("Packets_tcp: %llu\n", (unsigned long long)s->numpackets_tcp);
	printf("Packets_udp: %llu\n", (unsigned long long)s->numpackets_udp);
	printf("Packets_icmp: %llu\n", (unsigned long long)s->numpackets_icmp);
	printf("Packets_other: %llu\n", (unsigned long long)s->numpackets_other);
	printf("Bytes: %llu\n", (unsigned long long)s->numbytes);
	printf("Bytes_tcp: %llu\n", (unsigned long long)s->numbytes_tcp);
	printf("Bytes_udp: %llu\n", (unsigned long long)s->numbytes_udp);
	printf("Bytes_icmp: %llu\n", (unsigned long long)s->numbytes_icmp);
	printf("Bytes_other: %llu\n", (unsigned long long)s->numbytes_other);
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
		snprintf(error_string, ERR_SIZE, "Failed to open file %s: '%s'" , filename, strerror(errno));
		error_string[ERR_SIZE-1] = 0;
		*err = error_string;
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
	strncpy(file_header.ident, ident ? ident : "unknown" , IdentLen);
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
char	stat_filename[MAXPATHLEN];

	ZeroStat();
    if ( sfile == NULL )
		return;

	snprintf(stat_filename, MAXPATHLEN-1, "%s.stat", sfile);
    stat_filename[MAXPATHLEN-1] = 0;

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

