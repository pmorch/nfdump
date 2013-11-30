/*  This file is part of the nfdump project.
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
 *  $Id: nfstat.c 24 2005-04-01 12:07:30Z peter $
 *
 *  $LastChangedRevision: 24 $
 *	
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nfdump.h"
#include "netflow_v5.h"
#include "nf_common.h"
#include "util.h"
#include "nfstat.h"

struct StatParameter_s {
	char	*statname;		// name of -s option
	char	*HeaderInfo;	// How to name the field in the output header line
	uint32_t	offset;		// offset in the netflow record block
	uint32_t	mask;		// mask for value in 32bit word
	uint32_t	shift;		// number of bits to shift right to get final value
	int			ipconv;		// Convert number to IP readable Addr
} StatParameters[] ={
	{ "srcip",	 "Src IP Addr", OffsetSrcIP, MaskIP, 	  0,			1 },
	{ "dstip",	 "Dst IP Addr", OffsetDstIP, MaskIP, 	  0,			1 },
	{ "srcport", "   Src Port", OffsetPort,  MaskSrcPort, ShiftSrcPort, 0 },
	{ "dstport", "   Dst Port", OffsetPort,  MaskDstPort, ShiftDstPort, 0 },
	{ "srcas",	 "     Src AS", OffsetAS, 	 MaskSrcAS,   ShiftSrcAS,   0 },
	{ "dstas",	 "     Dst AS", OffsetAS, 	 MaskDstAS,   ShiftDstAS,   0 },
	{ NULL, 	 NULL, 			0, 			 0, 		  0,			0 }
};

extern uint32_t	byte_limit, packet_limit;
extern int byte_mode, packet_mode;
enum { NONE, LESS, MORE };


#define MaxMemBlocks	256

/* function prototypes */
static FlowTableRecord_t *hash_lookup_FlowTable(uint32_t *index_cache, uint8_t proto,
				uint32_t addr, uint32_t dstaddr, uint16_t port, uint16_t dstport);

static FlowTableRecord_t *hash_insert_FlowTable(uint32_t index_cache,
				uint32_t addr, uint32_t dstaddr, uint16_t port, uint16_t dstport);

static StatRecord_t *stat_hash_lookup(uint32_t addr);

static StatRecord_t *stat_hash_insert(uint32_t addr);

static void Expand_FlowTable_Blocks(void);

static void Expand_StatTable_Blocks(void);

static void PrintStatLine(StatRecord_t *StatData);

static void Make_TopN_aggregated(SortElement_t **topN_pkg, SortElement_t **topN_bytes, int topN, uint32_t *count );

// static SortElement_t *Make_TopN_packets(int topN, uint32_t *count);

// static SortElement_t *Make_TopN_bytes(int topN, uint32_t *count);

static SortElement_t *StatTopN_ip(int topN, uint32_t *count );

static void heapSort(SortElement_t *topN_ip, uint32_t array_size, int topN);

static void siftDown(SortElement_t *topN_ip, uint32_t root, uint32_t bottom);

/* locals */
static hash_FlowTable FlowTable;
static hash_StatTable StatTable;
static int	StatType;

static const double _1KB = 1024.0;
static const double _1MB = 1024.0 * 1024.0;
static const double _1GB = 1024.0 * 1024.0 * 1024.0;

#define mix(a,b,c) { \
	    a -= b; a -= c; a ^= (c>>13); \
	    b -= c; b -= a; b ^= (a<<8); \
	    c -= a; c -= b; c ^= (b>>13); \
	    a -= b; a -= c; a ^= (c>>12);  \
	    b -= c; b -= a; b ^= (a<<16); \
	    c -= a; c -= b; c ^= (b>>5); \
	    a -= b; a -= c; a ^= (c>>3);  \
	    b -= c; b -= a; b ^= (a<<10); \
	    c -= a; c -= b; c ^= (b>>15); \
}

/* Functions */
int Init_FlowTable(uint16_t NumBits, uint32_t Prealloc) {
uint32_t maxindex;

	if ( NumBits == 0 || NumBits > 31 ) {
		fprintf(stderr, "Numbits outside 1..31\n");
		exit(255);
	}
	maxindex = (1 << NumBits);
	FlowTable.IndexMask   = maxindex -1;
	FlowTable.NumBits     = NumBits;
	FlowTable.Prealloc    = Prealloc;
	FlowTable.bucket	  = (FlowTableRecord_t **)calloc(maxindex, sizeof(FlowTableRecord_t *));
	FlowTable.bucketcache = (FlowTableRecord_t **)calloc(maxindex, sizeof(FlowTableRecord_t *));
	if ( !FlowTable.bucket ) {
		perror("Can't allocate memory");
		return 0;
	}
	FlowTable.memblocks = (FlowTableRecord_t **)calloc(MaxMemBlocks, sizeof(FlowTableRecord_t *));
	if ( !FlowTable.memblocks ) {
		perror("Can't allocate memory");
		return 0;
	}
	FlowTable.memblocks[0] = (FlowTableRecord_t *)calloc(Prealloc, sizeof(FlowTableRecord_t));

	FlowTable.NumBlocks = 1;
	FlowTable.MaxBlocks = MaxMemBlocks;
	FlowTable.NextBlock = 0;
	FlowTable.NextElem  = 0;
	
	return 1;

} // End of Init_FlowTable

int Set_StatType(char *stat_type) {
int i=0;

	StatType = -1;
	while ( StatParameters[i].statname ) {
		if ( strncasecmp(stat_type, StatParameters[i].statname ,16) == 0 ) {
			StatType = i;
			break;
		}
		i++;
	}
 
	return StatType >= 0 ? 0 : 1;

} // End of Set_StatType

int Init_StatTable(uint16_t NumBits, uint32_t Prealloc) {
uint32_t maxindex;

	if ( NumBits == 0 || NumBits > 31 ) {
		fprintf(stderr, "Numbits outside 1..31n");
		exit(255);
	}
	maxindex = (1 << NumBits);
	StatTable.IndexMask   = maxindex -1;
	StatTable.NumBits     = NumBits;
	StatTable.Prealloc    = Prealloc;
	StatTable.bucket	  = (StatRecord_t **)calloc(maxindex, sizeof(StatRecord_t *));
	StatTable.bucketcache = (StatRecord_t **)calloc(maxindex, sizeof(StatRecord_t *));
	if ( !StatTable.bucket || !StatTable.bucketcache ) {
		perror("Init_StatTable memory error");
		return 0;
	}
	StatTable.memblocks = (StatRecord_t **)calloc(MaxMemBlocks, sizeof(StatRecord_t *));
	if ( !StatTable.memblocks ) {
		perror("Init_StatTable Memory error");
		return 0;
	}
	StatTable.memblocks[0] = (StatRecord_t *)calloc(Prealloc, sizeof(StatRecord_t));
	if ( !StatTable.memblocks[0] ) {
		perror("Init_StatTable Memory error");
		return 0;
	}

	StatTable.NumBlocks = 1;
	StatTable.MaxBlocks = MaxMemBlocks;
	StatTable.NextBlock = 0;
	StatTable.NextElem  = 0;
	
	return 1;

} // End of Init_StatTable

void Dispose_Tables(int flow_stat, int any_stat) {
unsigned int i;

	if ( flow_stat ) {
		free((void *)FlowTable.bucket);
		free((void *)FlowTable.bucketcache);
		for ( i=0; i<FlowTable.NumBlocks; i++ ) 
			free((void *)FlowTable.memblocks[i]);
		free((void *)FlowTable.memblocks);
	}

	if ( any_stat ) {
		free((void *)StatTable.bucket);
		for ( i=0; i<StatTable.NumBlocks; i++ ) 
			free((void *)StatTable.memblocks[i]);
		free((void *)StatTable.memblocks);
	}

} // End of Dispose_Tables

inline FlowTableRecord_t *hash_lookup_FlowTable(uint32_t *index_cache, uint8_t proto,
				uint32_t addr, uint32_t dstaddr, uint16_t port, uint16_t dstport ) {
uint32_t			index, a1, a2;
FlowTableRecord_t	*record;

	index = port ^ dstport;
	a1 = addr; a2 = dstaddr;
	mix(a1, a2, index);

	index = (index ^ ( index >> ( 32 - FlowTable.NumBits ))) & FlowTable.IndexMask;
	*index_cache = index;

	if ( FlowTable.bucket[index] == NULL )
		return NULL;

	record = FlowTable.bucket[index];
	while ( record ) {
		if ( ( record->ip1   == addr && record->ip2   == dstaddr &&
			   record->port1 == port && record->port2 == dstport &&
			   record->proto == proto ) )
			return record;
		record = record->next;
	}
	return NULL;

} // End of hash_lookup_FlowTable

inline StatRecord_t *stat_hash_lookup(uint32_t addr) {
uint32_t		index;
StatRecord_t	*record;

	index = addr & StatTable.IndexMask;
	if ( StatTable.bucket[index] == NULL )
		return NULL;

	record = StatTable.bucket[index];
	while ( record && ( record->stat_key != addr ) ) {
		record = record->next;
	}
	return record;

} // End of stat_hash_lookup

static void Expand_FlowTable_Blocks(void) {

	if ( FlowTable.NumBlocks >= FlowTable.MaxBlocks ) {
		FlowTable.MaxBlocks += MaxMemBlocks;
		FlowTable.memblocks = (FlowTableRecord_t **)realloc(FlowTable.memblocks,
						FlowTable.MaxBlocks * sizeof(FlowTableRecord_t *));
		if ( !FlowTable.memblocks ) {
			perror("Expand_FlowTable_Blocks Memory error");
			exit(250);
		}
	}
	FlowTable.memblocks[FlowTable.NumBlocks] = 
			(FlowTableRecord_t *)calloc(FlowTable.Prealloc, sizeof(FlowTableRecord_t));

	if ( !FlowTable.memblocks[FlowTable.NumBlocks] ) {
		perror("Expand_FlowTable_Blocks Memory error");
		exit(250);
	}
	FlowTable.NextBlock = FlowTable.NumBlocks++;
	FlowTable.NextElem  = 0;

} // End of Expand_FlowTable_Blocks

static void Expand_StatTable_Blocks(void) {

	if ( StatTable.NumBlocks >= StatTable.MaxBlocks ) {
		StatTable.MaxBlocks += MaxMemBlocks;
		StatTable.memblocks = (StatRecord_t **)realloc(StatTable.memblocks,
						StatTable.MaxBlocks * sizeof(StatRecord_t *));
		if ( !StatTable.memblocks ) {
			perror("Expand_StatTable_Blocks Memory error");
			exit(250);
		}
	}
	StatTable.memblocks[StatTable.NumBlocks] = 
			(StatRecord_t *)calloc(StatTable.Prealloc, sizeof(StatRecord_t));

	if ( !StatTable.memblocks[StatTable.NumBlocks] ) {
		perror("Expand_StatTable_Blocks Memory error");
		exit(250);
	}
	StatTable.NextBlock = StatTable.NumBlocks++;
	StatTable.NextElem  = 0;

} // End of Expand_StatTable_Blocks

inline static FlowTableRecord_t *hash_insert_FlowTable(uint32_t index_cache,
				uint32_t addr, uint32_t dstaddr, uint16_t port, uint16_t dstport) {
FlowTableRecord_t	*record;

	if ( FlowTable.NextElem >= FlowTable.Prealloc )
		Expand_FlowTable_Blocks();

	record = &(FlowTable.memblocks[FlowTable.NextBlock][FlowTable.NextElem]);
	FlowTable.NextElem++;
	record->next  = NULL;
	record->ip1   = addr;
	record->ip2   = dstaddr;
	record->port1 = port;
	record->port2 = dstport;

	if ( FlowTable.bucket[index_cache] == NULL ) 
		FlowTable.bucket[index_cache] = record;
	else 
		FlowTable.bucketcache[index_cache]->next = record;
	FlowTable.bucketcache[index_cache] = record;

	return record;

} // End of hash_insert_FlowTable

void list_insert(nf_record_t *nf_record) {
FlowTableRecord_t	*record;

	if ( FlowTable.NextElem >= FlowTable.Prealloc )
		Expand_FlowTable_Blocks();

	record = &(FlowTable.memblocks[FlowTable.NextBlock][FlowTable.NextElem]);
	FlowTable.NextElem++;

	record->next  		= NULL;
	record->ip1   		= nf_record->srcaddr;
	record->ip2   		= nf_record->dstaddr;
	record->port1 		= nf_record->srcport;
	record->port2 		= nf_record->dstport;
	record->bytes	   	= nf_record->dOctets;
	record->pkts	   	= nf_record->dPkts;
	record->first	   	= nf_record->First;
	record->last	   	= nf_record->Last;
	record->proto	   	= nf_record->prot;
	record->tcp_flags  	= nf_record->tcp_flags;
	record->tos  		= nf_record->tos;
	record->numflows 	= 1;

} // End of list_insert


inline static StatRecord_t *stat_hash_insert(uint32_t addr) {
uint32_t		index;
StatRecord_t	*record;

	if ( StatTable.NextElem >= StatTable.Prealloc )
		Expand_StatTable_Blocks();

	record = &(StatTable.memblocks[StatTable.NextBlock][StatTable.NextElem]);
	StatTable.NextElem++;
	record->next     = NULL;
	record->stat_key = addr;

	index = addr & StatTable.IndexMask;
	if ( StatTable.bucket[index] == NULL ) 
		StatTable.bucket[index] = record;
	else
		StatTable.bucketcache[index]->next = record;
	StatTable.bucketcache[index] = record;
	
	return record;

} // End of stat_hash_insert

int AddStat(nf_header_t *nf_header, nf_record_t *nf_record, 
				int flow_stat, int any_stat ) {
FlowTableRecord_t	*StatTable_record;
StatRecord_t		*stat_record;
time_t				start_time, end_time;
uint32_t			index_cache, value;

	start_time = nf_record->First;
	end_time   = nf_record->Last;
	
	if ( flow_stat ) {
		// Update netflow statistics
		StatTable_record = hash_lookup_FlowTable(&index_cache, nf_record->prot,
						nf_record->srcaddr, nf_record->dstaddr, nf_record->srcport, nf_record->dstport);
		if ( StatTable_record ) {
			StatTable_record->bytes += nf_record->dOctets;
			StatTable_record->pkts  += nf_record->dPkts;
			if ( start_time < StatTable_record->first ) 
				StatTable_record->first = start_time;
			if ( end_time > StatTable_record->last ) 
				StatTable_record->last = end_time;
			StatTable_record->numflows++;
	
		} else {
			StatTable_record = hash_insert_FlowTable(index_cache, 
							nf_record->srcaddr, nf_record->dstaddr, nf_record->srcport, nf_record->dstport);
			if ( !StatTable_record )
				return -1;
	
			StatTable_record->bytes	 	= nf_record->dOctets;
			StatTable_record->pkts	 	= nf_record->dPkts;
			StatTable_record->first	 	= start_time;
			StatTable_record->last		= end_time;
			StatTable_record->tos		= nf_record->tos;
			StatTable_record->tcp_flags	= nf_record->tcp_flags;
			StatTable_record->proto	 	= nf_record->prot;
			StatTable_record->numflows 	= 1;
		}
	}

	// Update IP statistics
	if ( any_stat ) {
		int offset = StatParameters[StatType].offset;
		value = ((uint32_t *)nf_record)[offset] & StatParameters[StatType].mask;
		value = value >> StatParameters[StatType].shift;
		stat_record = stat_hash_lookup(value);
		if ( stat_record ) {
			stat_record->bytes += nf_record->dOctets;
			stat_record->pkts  += nf_record->dPkts;
			stat_record->tcp_flags	|= stat_record->tcp_flags;
			if ( start_time < stat_record->first ) 
				stat_record->first = start_time;
			if ( end_time > stat_record->last ) 
				stat_record->last = end_time;
			stat_record->numflows++;
	
		} else {
			stat_record = stat_hash_insert(value);
			if ( !stat_record )
				return -1;
	
			stat_record->bytes    	= nf_record->dOctets;
			stat_record->pkts	   	= nf_record->dPkts;
			stat_record->first    	= start_time;
			stat_record->last	   	= end_time;
			stat_record->tos		= nf_record->tos;
			stat_record->tcp_flags	= nf_record->tcp_flags;
			stat_record->proto		= nf_record->prot;
			stat_record->numflows 	= 1;
		}
	}

	return 0;

} // End of AddStat

static void PrintStatLine(StatRecord_t *StatData) {
char		*str, valstr[32], datestr[64];
double		fsize;
uint32_t	duration, usize;
char		scale;
struct tm	*tbuff;
struct in_addr a;

	if ( StatParameters[StatType].ipconv ) {
		fsize = 0;
		usize = 0;
		a.s_addr = htonl(StatData->stat_key);
		str = inet_ntoa(a);
		strncpy(valstr, str, 15);
		valstr[15] = 0;
	} else {
		snprintf(valstr, 15, "%u", StatData->stat_key);
		valstr[31] = 0;
	}

	if ( StatData->bytes >= _1GB ) {
		fsize = (double)StatData->bytes / _1GB;
		scale = 'G';
	} else if ( StatData->bytes >= _1MB ) {
		fsize = (double)StatData->bytes / _1MB;
		scale = 'M';
	} else if ( StatData->bytes >= _1KB ) {
		fsize = (double)StatData->bytes / _1KB;
		scale = 'K';
	} else  {
		usize = StatData->bytes;
		scale = ' ';
	} 
	duration = StatData->last - StatData->first;
	
	tbuff = localtime(&StatData->first);
	if ( !tbuff ) {
		perror("Error time convert");
		exit(250);
	}
	strftime(datestr, 63, "%b %d %Y %T", tbuff);

	if ( scale == ' ' ) 
		printf("%s %8i %15s %8llu %6u %cB %7llu\n", datestr, duration, 
						valstr, StatData->pkts, usize, scale, StatData->numflows );
	else
		printf("%s %8i %15s %8llu %6.1f %cB %7llu\n", datestr, duration, 
						valstr, StatData->pkts, fsize, scale, StatData->numflows );

} // End of PrintStatLine

void ReportAggregated(printer_t print_record, uint32_t limitflows, int date_sorted) {
FlowTableRecord_t	*r;
nf_record_t			nf_record;
SortElement_t 		*SortList;
uint32_t 			i, j, tmp;
uint32_t			maxindex, c;
char				*string;

	maxindex = ( FlowTable.NextBlock * FlowTable.Prealloc ) + FlowTable.NextElem;
	if ( date_sorted ) {
		// Sort according the date
		SortList = (SortElement_t *)calloc(maxindex+1, sizeof(SortElement_t));

		if ( !SortList ) {
			perror("Can't allocate Top N lists: \n");
			return;
		}

		// preset SortList table - still unsorted
		c = 0;
		for ( i=0; i <= FlowTable.IndexMask; i++ ) {
			r = FlowTable.bucket[i];
			// foreach elem in this bucket
			while ( r ) {
				// we want to sort only those flows which pass the packet or byte limits
				if ( byte_limit ) {
					if (( byte_mode == LESS && r->bytes >= byte_limit ) ||
						( byte_mode == MORE && r->bytes  <= byte_limit ) ) {
						r = r->next;
						continue;
					}
				}
				if ( packet_limit ) {
					if (( packet_mode == LESS && r->pkts >= packet_limit ) ||
						( packet_mode == MORE && r->pkts  <= packet_limit ) ) {
						r = r->next;
						continue;
					}
				}
				
				SortList[c].count  = r->first;	// sort according the date
				SortList[c].record = (void *)r;
				r = r->next;
				c++;
			}
		}

		SortList[maxindex].count = 0;
		// heapSort(SortList, maxindex, 0);
		if ( c >= 2 )
 			heapSort(SortList, c, 0);

		if ( limitflows && limitflows < maxindex )
			maxindex = limitflows;
		for ( i = 0; i < maxindex; i++ ) {

			nf_record.srcaddr 	= ((FlowTableRecord_t *)(SortList[i].record))->ip1;
			nf_record.dstaddr 	= ((FlowTableRecord_t *)(SortList[i].record))->ip2;
			nf_record.srcport 	= ((FlowTableRecord_t *)(SortList[i].record))->port1;
			nf_record.dstport 	= ((FlowTableRecord_t *)(SortList[i].record))->port2;
			nf_record.dOctets 	= ((FlowTableRecord_t *)(SortList[i].record))->bytes;
			nf_record.dPkts   	= ((FlowTableRecord_t *)(SortList[i].record))->pkts;
			nf_record.First   	= ((FlowTableRecord_t *)(SortList[i].record))->first;
			nf_record.Last    	= ((FlowTableRecord_t *)(SortList[i].record))->last;
			nf_record.prot    	= ((FlowTableRecord_t *)(SortList[i].record))->proto;
			nf_record.tcp_flags	= ((FlowTableRecord_t *)(SortList[i].record))->tcp_flags;
			nf_record.tos    	= ((FlowTableRecord_t *)(SortList[i].record))->tos;

			print_record((void *)&nf_record, &string);
			printf("%s %3llu\n", string, ((FlowTableRecord_t *)(SortList[i].record))->numflows);

		}

	} else {
		// print them as they came
		c = 0;
		for ( i=0; i < FlowTable.NumBlocks; i++ ) {
			tmp = i * FlowTable.Prealloc;
			for ( j=0; j < FlowTable.Prealloc; j++ ) {
				r = &(FlowTable.memblocks[i][j]);
				if ( (tmp + j) < maxindex ) {
					if ( limitflows && c >= limitflows )
						return;

					// we want to print only those flows which pass the packet or byte limits
					if ( byte_limit ) {
						if (( byte_mode == LESS && r->bytes >= byte_limit ) ||
							( byte_mode == MORE && r->bytes  <= byte_limit ) ) {
							continue;
						}
					}
					if ( packet_limit ) {
						if (( packet_mode == LESS && r->pkts >= packet_limit ) ||
							( packet_mode == MORE && r->pkts  <= packet_limit ) ) {
							continue;
						}
					}

					nf_record.srcaddr 	= r->ip1;
					nf_record.dstaddr 	= r->ip2;
					nf_record.srcport 	= r->port1;
					nf_record.dstport 	= r->port2;
					nf_record.dOctets 	= r->bytes;
					nf_record.dPkts   	= r->pkts;
					nf_record.First   	= r->first;
					nf_record.Last    	= r->last;
					nf_record.prot    	= r->proto;
					nf_record.tcp_flags	= r->tcp_flags;
					nf_record.tos    	= r->tos;

					print_record((void *)&nf_record, &string);
					printf("%s %3llu\n", string, r->numflows);

					c++;
				}
			}
		}
	}

} // End of ReportAggregated

void ReportStat(char *record_header, printer_t print_record, int topN, int flow_stat, int any_stat) {
SortElement_t 	*topN_pkg;
SortElement_t 	*topN_bytes;
SortElement_t	*topN_list;
nf_record_t		nf_record;
uint32_t		numflows, maxindex;
int32_t 			i, j;
char			*string;

	if ( flow_stat ) {
		Make_TopN_aggregated(&topN_pkg, &topN_bytes, topN, &numflows);
		printf("Aggregated flows %u\n", numflows);
		printf("Time window: %s\n", TimeString());
		if ( !topN_pkg || !topN_bytes ) 
			return;
	
		printf("Top %i flows packet count:\n", topN);
		if ( record_header ) 
			printf("%s\n", record_header);

		for ( i=topN-1; i>=0; i--) {
			if ( !topN_pkg[i].count )
				break;

			nf_record.srcaddr 	= ((FlowTableRecord_t *)(topN_pkg[i].record))->ip1;
			nf_record.dstaddr 	= ((FlowTableRecord_t *)(topN_pkg[i].record))->ip2;
			nf_record.srcport 	= ((FlowTableRecord_t *)(topN_pkg[i].record))->port1;
			nf_record.dstport 	= ((FlowTableRecord_t *)(topN_pkg[i].record))->port2;
			nf_record.dOctets 	= ((FlowTableRecord_t *)(topN_pkg[i].record))->bytes;
			nf_record.dPkts   	= ((FlowTableRecord_t *)(topN_pkg[i].record))->pkts;
			nf_record.First   	= ((FlowTableRecord_t *)(topN_pkg[i].record))->first;
			nf_record.Last    	= ((FlowTableRecord_t *)(topN_pkg[i].record))->last;
			nf_record.prot    	= ((FlowTableRecord_t *)(topN_pkg[i].record))->proto;
			nf_record.tcp_flags	= ((FlowTableRecord_t *)(topN_pkg[i].record))->tcp_flags;
			nf_record.tos    	= ((FlowTableRecord_t *)(topN_pkg[i].record))->tos;

			print_record((void *)&nf_record, &string);
			printf("%s %3llu\n", string, ((FlowTableRecord_t *)(topN_pkg[i].record))->numflows);

		}

		printf("\nTop %i flows byte count:\n", topN);
		if ( record_header ) 
			printf("%s\n", record_header);

		for ( i=topN-1; i>=0; i--) {
			if ( !topN_bytes[i].count )
				break;

			nf_record.srcaddr 	= ((FlowTableRecord_t *)(topN_bytes[i].record))->ip1;
			nf_record.dstaddr 	= ((FlowTableRecord_t *)(topN_bytes[i].record))->ip2;
			nf_record.srcport 	= ((FlowTableRecord_t *)(topN_bytes[i].record))->port1;
			nf_record.dstport 	= ((FlowTableRecord_t *)(topN_bytes[i].record))->port2;
			nf_record.dOctets 	= ((FlowTableRecord_t *)(topN_bytes[i].record))->bytes;
			nf_record.dPkts   	= ((FlowTableRecord_t *)(topN_bytes[i].record))->pkts;
			nf_record.First   	= ((FlowTableRecord_t *)(topN_bytes[i].record))->first;
			nf_record.Last    	= ((FlowTableRecord_t *)(topN_bytes[i].record))->last;
			nf_record.prot    	= ((FlowTableRecord_t *)(topN_bytes[i].record))->proto;
			nf_record.tcp_flags	= ((FlowTableRecord_t *)(topN_bytes[i].record))->tcp_flags;
			nf_record.tos    	= ((FlowTableRecord_t *)(topN_bytes[i].record))->tos;

			print_record((void *)&nf_record, &string);
			printf("%s %3llu\n", string, ((FlowTableRecord_t *)(topN_bytes[i].record))->numflows);

		}
		printf("\n");
	}

	if ( any_stat ) {
		topN_list = StatTopN_ip(topN, &numflows);
		printf("Number of IP addr %u\n", numflows);
		printf("Time window: %s\n", TimeString());
		printf("Top %i %s counts:\n", topN, StatParameters[StatType].HeaderInfo);

		//      Aug 20 2004 09:57:00     1980     value          303    303  B       3
		printf("Date first seen           Len     %s  Packets     Bytes   Flows\n", 
			StatParameters[StatType].HeaderInfo);

		maxindex = ( StatTable.NextBlock * StatTable.Prealloc ) + StatTable.NextElem;
		j = numflows - topN;
		j = j < 0 ? 0 : j;
		if ( topN == 0 )
			j = 0;

		for ( i=numflows-1; i>=j ; i--) {
			if ( !topN_list[i].count )
				break;
			PrintStatLine((StatRecord_t *)topN_list[i].record);
		}
		free((void *)topN_list);
	}

} // End of ReportStat

/*
 * Generate the top N lists for packets and bytes in one run
 */
void Make_TopN_aggregated(SortElement_t **topN_pkg, SortElement_t **topN_bytes, int topN, uint32_t *count) {
FlowTableRecord_t	*r, *r1, *r2;
unsigned int		i;
int					j;
uint64_t	   		c1, c2, c;

	*topN_pkg   = (SortElement_t *)calloc(topN, sizeof(SortElement_t));
	*topN_bytes = (SortElement_t *)calloc(topN, sizeof(SortElement_t));
	if ( !*topN_pkg || !*topN_bytes ) {
		perror("Can't allocate Top N lists: \n");
		*topN_pkg = *topN_bytes = NULL;
		return ;
	}

	c = 0;
	// Iterate through all buckets
	for ( i=0; i <= FlowTable.IndexMask; i++ ) {
		r = FlowTable.bucket[i];
		// foreach elem in this bucket
		while ( r ) {

			// we want to sort only those flows which pass the packet or byte limits
			if ( byte_limit ) {
				if (( byte_mode == LESS && r->bytes >= byte_limit ) ||
					( byte_mode == MORE && r->bytes  <= byte_limit ) ) {
					r = r->next;
					continue;
				}
			}
			if ( packet_limit ) {
				if (( packet_mode == LESS && r->pkts >= packet_limit ) ||
					( packet_mode == MORE && r->pkts  <= packet_limit ) ) {
					r = r->next;
					continue;
				}
			}

			c++;
			/* packet top N list */
			if ( r->pkts > (*topN_pkg)[0].count ) {
				/* element value is bigger than smallest value in topN */
				c1 = r->pkts;
				r1 = r;
				for (j=topN-1; j>=0; j-- ) {
					if ( c1 > (*topN_pkg)[j].count ) {
						c2 = (*topN_pkg)[j].count;
						r2 = (*topN_pkg)[j].record;
						(*topN_pkg)[j].count 	= c1;
						(*topN_pkg)[j].record	= r1;
						c1 = c2; r1 = r2;
					}
				}
			} // if pkts

			/* byte top N list */
			if ( r->bytes > (*topN_bytes)[0].count ) {
				/* element value is bigger than smallest value in topN */
				c1 = r->bytes;
				r1 = r;
				for (j=topN-1; j>=0; j-- ) {
					if ( c1 > (*topN_bytes)[j].count ) {
						c2 = (*topN_bytes)[j].count;
						r2 = (*topN_bytes)[j].record;
						(*topN_bytes)[j].count 	= c1;
						(*topN_bytes)[j].record = r1;
						c1 = c2; r1 = r2;
					}
				}
			} // if bytes

			// next elem in bucket
			r = r->next;
		} // foreach element
	}
	*count = c;

} // End of Make_TopN_aggregated

void PrintSortedFlows(printer_t print_record, uint32_t limitflows) {
FlowTableRecord_t	*r;
SortElement_t 		*SortList;
nf_record_t			nf_record;
unsigned int		i, j, tmp;
uint32_t			maxindex, c;
char				*string;

	maxindex = ( FlowTable.NextBlock * FlowTable.Prealloc ) + FlowTable.NextElem;
	SortList = (SortElement_t *)calloc(maxindex+1, sizeof(SortElement_t));

	if ( !SortList ) {
		perror("Can't allocate Top N lists: \n");
		return;
	}

	// preset SortList table - still unsorted
	c = 0;
	for ( i=0; i < FlowTable.NumBlocks; i++ ) {
		tmp = i * FlowTable.Prealloc;
		for ( j=0; j < FlowTable.Prealloc; j++ ) {
			r = &(FlowTable.memblocks[i][j]);
			if ( (tmp + j) < maxindex ) {
				SortList[c].count  = r->first;	// sort according the date
				SortList[c].record = (void *)r;
				c++;
			}
		}
	}

	SortList[maxindex].count = 0;
	heapSort(SortList, maxindex, 0);

	if ( limitflows && limitflows < maxindex )
		maxindex = limitflows;
	for ( i=0; i<maxindex; i++ ) {
		r = SortList[i].record;

		nf_record.srcaddr 	= r->ip1;
		nf_record.dstaddr 	= r->ip2;
		nf_record.srcport 	= r->port1;
		nf_record.dstport 	= r->port2;
		nf_record.dOctets 	= r->bytes;
		nf_record.dPkts   	= r->pkts;
		nf_record.First   	= r->first;
		nf_record.Last    	= r->last;
		nf_record.prot    	= r->proto;
		nf_record.tcp_flags	= r->tcp_flags;
		nf_record.tos    	= r->tos;

		print_record((void *)&nf_record, &string);

		if ( string )
			printf("%s\n", string);
	}
	
	free(SortList);

} // End of PrintSortedFlows

/* 
 * Some different implementation of statistics
 *
static SortElement_t *Make_TopN_packets(int topN, uint32_t *count) {
FlowTableRecord_t	*r;
SortElement_t 		*topN_SortList;
unsigned int		i;
uint32_t			maxindex, c;

	maxindex = ( FlowTable.NextBlock * FlowTable.Prealloc ) + FlowTable.NextElem;
	topN_SortList = (SortElement_t *)calloc(maxindex+1, sizeof(SortElement_t));

	if ( !topN_SortList ) {
		perror("Can't allocate Top N lists: \n");
		return NULL;
	}

	// preset topN_SortList table - still unsorted
	c = 0;
	// Iterate through all buckets
	for ( i=0; i <= FlowTable.IndexMask; i++ ) {
		r = FlowTable.bucket[i];
		// foreach elem in this bucket
		while ( r ) {
			// next elem in bucket
			topN_SortList[c].count  = r->pkts;
			topN_SortList[c].record = (void *)r;
			r = r->next;
			c++;
		}
	}
	*count = c;

	topN_SortList[maxindex].count = 0;
	heapSort(topN_SortList, maxindex, topN);
	return topN_SortList;

} // End of Make_TopN_packets

static SortElement_t *Make_TopN_bytes(int topN, uint32_t *count) {
SortElement_t 		*topN_bytes_list;
FlowTableRecord_t	*r;
unsigned int		i;
uint32_t			maxindex, c;

	maxindex = ( FlowTable.NextBlock * FlowTable.Prealloc ) + FlowTable.NextElem;
	topN_bytes_list = (SortElement_t *)calloc(maxindex+1, sizeof(SortElement_t));

	if ( !topN_bytes_list ) {
		perror("Can't allocate Top N lists: \n");
		return NULL;
	}

	// preset topN_SortList table - still unsorted
	c = 0;
	// Iterate through all buckets
	for ( i=0; i <= FlowTable.IndexMask; i++ ) {
		r = FlowTable.bucket[i];
		// foreach elem in this bucket
		while ( r ) {
			// next elem in bucket
			topN_bytes_list[c].count  = r->pkts;
			topN_bytes_list[c].record = (void *)r;
			r = r->next;
			c++;
		}
	}
	*count = c;

	topN_bytes_list[maxindex].count = 0;
	heapSort(topN_bytes_list, maxindex, topN);
	return topN_bytes_list;

} // End of Make_TopN_bytes

*/

static SortElement_t *StatTopN_ip(int topN, uint32_t *count ) {
SortElement_t 		*topN_list;
StatRecord_t		*r;
unsigned int		i;
uint32_t	   		c, maxindex;

	maxindex  = ( StatTable.NextBlock * StatTable.Prealloc ) + StatTable.NextElem;
	topN_list = (SortElement_t *)calloc(maxindex+1, sizeof(SortElement_t));	// +1 for heapsort bug

	if ( !topN_list ) {
		perror("Can't allocate Top N lists: \n");
		return NULL;
	}

	// preset topN_list table - still unsorted
	c = 0;
	// Iterate through all buckets
	for ( i=0; i <= StatTable.IndexMask; i++ ) {
		r = StatTable.bucket[i];
		// foreach elem in this bucket
		while ( r ) {
			// next elem in bucket

			// we want to sort only those flows which pass the packet or byte limits
			if ( byte_limit ) {
				if (( byte_mode == LESS && r->bytes >= byte_limit ) ||
					( byte_mode == MORE && r->bytes  <= byte_limit ) ) {
					r = r->next;
					continue;
				}
			}
			if ( packet_limit ) {
				if (( packet_mode == LESS && r->pkts >= packet_limit ) ||
					( packet_mode == MORE && r->pkts  <= packet_limit ) ) {
					r = r->next;
					continue;
				}
			}
			topN_list[c].count  = r->numflows;
			topN_list[c].record = (void *)r;
			r = r->next;
			c++;
		} // foreach element
	}
	*count = c;
	// printf ("Sort %u flows\n", c);
	
	topN_list[maxindex].count = 0;

	// Sorting makes only sense, when 2 or more flows are left
	if ( c >= 2 )
 		heapSort(topN_list, c, topN > c ? c : topN);

/*
	for ( i = 0; i < maxindex; i++ ) 
		printf("%i, %llu %llu\n", i, topN_list[i].count, topN_list[i].record);
*/
	return topN_list;
	
} // End of StatTopN_ip


static void heapSort(SortElement_t *SortElement, uint32_t array_size, int topN) {
int32_t		i;
uint32_t	top_count;
SortElement_t temp;

	for (i = (array_size >> 1)-1; i >= 0; i--)
		siftDown(SortElement, i, array_size);

	top_count = 1;
	for (i = array_size-1; i >= 1; i--) {
		temp = SortElement[0];
		SortElement[0] = SortElement[i];
		SortElement[i] = temp;
		siftDown(SortElement, 0, i-1);
		/* 
		 * if we need to know only the first top N skip
		 * the sorting of the rest. For topN == 0 -> all gets sorted
		 * as top_count is never 0
		 */
		if ( top_count == topN ) {
			return;
		}
		top_count++;
	}

} // End of heapSort

static void siftDown(SortElement_t *SortElement, uint32_t root, uint32_t bottom) {
uint32_t	maxChild;
SortElement_t temp;
int done;

	done = 0;
	while (((root << 1) <= bottom) && (!done)) {
		if ((root << 1) == bottom)
			maxChild = root << 1;
		else if (SortElement[root << 1].count > SortElement[(root << 1) + 1].count)
			maxChild = root << 1;
		else
			maxChild = (root << 1) + 1;

		if (SortElement[root].count < SortElement[maxChild].count) {
			temp = SortElement[root];
			SortElement[root] = SortElement[maxChild];
			SortElement[maxChild] = temp;
			root = maxChild;
		} else
		done = 1;
	}
} // End of siftDown

