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
 *  $Id: nfstat.c 53 2005-11-17 07:45:34Z peter $
 *
 *  $LastChangedRevision: 53 $
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
#include "panonymizer.h"
#include "nfstat.h"

struct flow_element_s {
	uint32_t	offset;		// set in the netflow record block
	uint32_t	mask;		// mask for value in 32bit word
	uint32_t	shift;		// number of bits to shift right to get final value
};

struct StatParameter_s {
	char					*statname;		// name of -s option
	char					*HeaderInfo;	// How to name the field in the output header line
	struct flow_element_s	element[2];		// what element(s) in flow record is used for statistics.
											// need 2 elements to be able to get src/dst stats in one stat record
	uint8_t					num_elem;		// number of elements used. 1 ord 2
	uint8_t					ipconv;			// is an IP address: Convert number to readable IP Addr
} StatParameters[] ={
	// flow record stst
	{ "record",	 "", 			{ {0,0, 0},									{0,0,0} }, 								   1, 0},

	// 9 possible flow element stats 
	{ "srcip",	 "Src IP Addr", { {OffsetSrcIP, MaskIP, 0}, 				{0,0,0} }, 								   1, 1},
	{ "dstip",	 "Dst IP Addr", { {OffsetDstIP, MaskIP, 0}, 				{0,0,0} }, 								   1, 1},
	{ "ip",	 	 "    IP Addr", { {OffsetSrcIP, MaskIP, 0}, 				{OffsetDstIP, MaskIP, 0} }, 			   2, 1},
	{ "srcport", "   Src Port", { {OffsetPort, MaskSrcPort, ShiftSrcPort}, 	{0,0,0} }, 								   1, 0},
	{ "dstport", "   Dst Port", { {OffsetPort, MaskDstPort, ShiftDstPort}, 	{0,0,0} }, 								   1, 0},
	{ "port", 	 "       Port", { {OffsetPort, MaskSrcPort, ShiftSrcPort}, 	{OffsetPort, MaskDstPort, ShiftDstPort} }, 2, 0},
	{ "srcas",	 "     Src AS", { {OffsetAS, MaskSrcAS, ShiftSrcAS},  		{0,0,0} }, 								   1, 0},
	{ "dstas",	 "     Dst AS", { {OffsetAS, MaskDstAS, ShiftDstAS},  		{0,0,0} }, 								   1, 0},
	{ "as",	 	 "         AS", { {OffsetAS, MaskSrcAS, ShiftSrcAS},  		{OffsetAS, MaskDstAS, ShiftDstAS} }, 	   2, 0},

	{ NULL, 	 NULL, 			{ {0,0, 0},									{0,0,0} }, 								   1, 0}
};

static const uint32_t NumOrders = 6;	// Number of Stats in enum StatTypes
enum StatTypes { FLOWS = 0, PACKETS, BYTES, PPS, BPS, BPP };

struct StatRequest_s {
	int16_t		StatType;	// value out of enum StatTypes
	uint16_t	order_bits;	// bits 0: flows 1: packets 2: bytes 3: pps 4: bps, 5 bpp
} StatRequest[9];			// 9 = number of possible flow element stats

uint32_t	flow_stat_order;
/* 
 * pps, bps and bpp are not directly available in the flow/stat record
 * therefore we need a function to calculate these values
 */
typedef uint32_t (*order_proc_t)(CommonRecord_t *);

/* order functions */
static inline uint32_t	pps_function(CommonRecord_t *record);

static inline uint32_t	bps_function(CommonRecord_t *record);

static inline uint32_t	bpp_function(CommonRecord_t *record);

struct order_mode_s {
	char		 *string;	// Stat name 
	int			 val;		// order bit set results in this value
	order_proc_t function;	// Function to call if value not directly available in record
} order_mode[] = {
	{ "flows",    1, NULL},
	{ "packets",  2, NULL},
	{ "bytes",    4, NULL},
	{ "pps", 	  8, pps_function},
	{ "bps", 	 16, bps_function},
	{ "bpp", 	 32, bpp_function},
	{ NULL,       0, NULL}
};


extern uint32_t	byte_limit, packet_limit;
extern int byte_mode, packet_mode;
enum { NONE, LESS, MORE };

#define MaxMemBlocks	256

/* function prototypes */
static int ParseStatString(char *str, int16_t	*StatType, uint16_t *order_bits, int *flow_record_stat);

static inline FlowTableRecord_t *hash_lookup_FlowTable(uint32_t *index_cache, uint8_t proto,
				uint32_t addr, uint32_t dstaddr, uint16_t port, uint16_t dstport);

static inline FlowTableRecord_t *hash_insert_FlowTable(uint32_t index_cache,
				uint32_t addr, uint32_t dstaddr, uint16_t port, uint16_t dstport);

static inline StatRecord_t *stat_hash_lookup(uint32_t addr, int hash_num);

static inline StatRecord_t *stat_hash_insert(uint32_t addr, int hash_num);

static void Expand_FlowTable_Blocks(void);

static void Expand_StatTable_Blocks(int hash_num);

static inline void MapRecord(flow_record_t *flow_record, void *record);

static void PrintStatLine(StatRecord_t *StatData, int ipconv, int anon);

static void Create_topN_FlowStat(SortElement_t **topN_lists, int order, int topN, uint32_t *count );

// static SortElement_t *Make_TopN_packets(int topN, uint32_t *count);

// static SortElement_t *Make_TopN_bytes(int topN, uint32_t *count);

static SortElement_t *StatTopN(int topN, uint32_t *count, int hash_num, int order );

static inline void RankValue(FlowTableRecord_t *r, uint64_t val, int topN, SortElement_t *topN_list);

static void heapSort(SortElement_t *SortElement, uint32_t array_size, int topN);

static void siftDown(SortElement_t *SortElement, uint32_t root, uint32_t bottom);

/* locals */
#ifndef __SUNPRO_C
static 
#endif
hash_FlowTable FlowTable;

#ifndef __SUNPRO_C
static 
#endif 
hash_StatTable *StatTable;

static int	NumStats = 0, DefaultOrder;

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

static uint32_t	pps_function(CommonRecord_t *record) {
uint64_t		duration;

	/* duration in msec */
	duration = 1000*(record->last - record->first) + record->msec_last - record->msec_first;
	if ( duration == 0 )
		return 0;
	else 
		return ( 1000LL * (uint64_t)record->counter[PACKETS] ) / duration;

} // End of pps_function

static uint32_t	bps_function(CommonRecord_t *record) {
uint64_t		duration;

	duration = 1000*(record->last - record->first) + record->msec_last - record->msec_first;
	if ( duration == 0 )
		return 0;
	else 
		return ( 8000LL * (uint64_t)record->counter[BYTES] ) / duration;	/* 8 bits per Octet - x 1000 for msec */

} // End of bps_function

static uint32_t	bpp_function(CommonRecord_t *record) {

	return record->counter[BYTES] / record->counter[PACKETS];

} // End of bpp_function

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
	FlowTable.memblock = (FlowTableRecord_t **)calloc(MaxMemBlocks, sizeof(FlowTableRecord_t *));
	if ( !FlowTable.memblock ) {
		perror("Can't allocate memory");
		return 0;
	}
	FlowTable.memblock[0] = (FlowTableRecord_t *)calloc(Prealloc, sizeof(FlowTableRecord_t));

	FlowTable.NumBlocks = 1;
	FlowTable.MaxBlocks = MaxMemBlocks;
	FlowTable.NextBlock = 0;
	FlowTable.NextElem  = 0;
	
	if ( !flow_stat_order ) 
		flow_stat_order = DefaultOrder;

	return 1;

} // End of Init_FlowTable

int Init_StatTable(uint16_t NumBits, uint32_t Prealloc) {
uint32_t maxindex;
int		 hash_num;

	if ( NumBits == 0 || NumBits > 31 ) {
		fprintf(stderr, "Numbits outside 1..31\n");
		exit(255);
	}

	maxindex = (1 << NumBits);

	StatTable = (hash_StatTable *)calloc(NumStats, sizeof(hash_StatTable));
	if ( !StatTable ) {
		perror("Init_StatTable memory error");
		return 0;
	}

	for ( hash_num=0; hash_num<NumStats; hash_num++ ) {
		StatTable[hash_num].IndexMask   = maxindex -1;
		StatTable[hash_num].NumBits     = NumBits;
		StatTable[hash_num].Prealloc    = Prealloc;
		StatTable[hash_num].bucket	  	= (StatRecord_t **)calloc(maxindex, sizeof(StatRecord_t *));
		StatTable[hash_num].bucketcache = (StatRecord_t **)calloc(maxindex, sizeof(StatRecord_t *));
		if ( !StatTable[hash_num].bucket || !StatTable[hash_num].bucketcache ) {
			perror("Init_StatTable memory error");
			return 0;
		}
		StatTable[hash_num].memblock = (StatRecord_t **)calloc(MaxMemBlocks, sizeof(StatRecord_t *));
		if ( !StatTable[hash_num].memblock ) {
			perror("Init_StatTable Memory error");
			return 0;
		}
		StatTable[hash_num].memblock[0] = (StatRecord_t *)calloc(Prealloc, sizeof(StatRecord_t));
		if ( !StatTable[hash_num].memblock[0] ) {
			perror("Init_StatTable Memory error");
			return 0;
		}
	
		StatTable[hash_num].NumBlocks = 1;
		StatTable[hash_num].MaxBlocks = MaxMemBlocks;
		StatTable[hash_num].NextBlock = 0;
		StatTable[hash_num].NextElem  = 0;

		if ( StatRequest[hash_num].order_bits == 0 ) {
			StatRequest[hash_num].order_bits = DefaultOrder;
		}
	}

	return 1;

} // End of Init_StatTable

void Dispose_Tables(int flow_stat, int element_stat) {
unsigned int i, hash_num;

	if ( flow_stat ) {
		free((void *)FlowTable.bucket);
		free((void *)FlowTable.bucketcache);
		for ( i=0; i<FlowTable.NumBlocks; i++ ) 
			free((void *)FlowTable.memblock[i]);
		free((void *)FlowTable.memblock);
	}

	if ( element_stat ) {
		for ( hash_num=0; hash_num<NumStats; hash_num++ ) {
			free((void *)StatTable[hash_num].bucket);
			for ( i=0; i<StatTable[hash_num].NumBlocks; i++ ) 
				free((void *)StatTable[hash_num].memblock[i]);
			free((void *)StatTable[hash_num].memblock);
		}
	}

} // End of Dispose_Tables

int SetStat(char *str, int *element_stat, int *flow_stat) {
int			flow_record_stat = 0;
int16_t 	StatType   = 0;
uint16_t	order_bits = 0;

	if ( ParseStatString(str, &StatType, &order_bits, &flow_record_stat) ) {
		if ( flow_record_stat ) {
			flow_stat_order = order_bits;
			*flow_stat = 1;
		} else {
			StatRequest[NumStats].StatType 	 = StatType;
			StatRequest[NumStats].order_bits = order_bits;
			NumStats++;
			*element_stat = 1;
		}
		return 1;
	} else {
		return 0;
	}

} // End of SetStat

static int ParseStatString(char *str, int16_t	*StatType, uint16_t *order_bits, int *flow_record_stat) {
char	*s, *q, *r;
int i=0;

	if ( NumStats >= 9 )
		return 0;

	s = strdup(str);
	q = strchr(s, '/');
	if ( q ) 
		*q = 0;

	i = 0;
	// check for a valid stat name
	while ( StatParameters[i].statname ) {
		if ( strncasecmp(s, StatParameters[i].statname ,16) == 0 ) {
			// set flag if it's the flow record stat request
			*flow_record_stat = strncasecmp(s, "record", 16) == 0;
			break;
		}
		i++;
	}

	// if so - initialize type and order_bits
 	if ( StatParameters[i].statname ) {
		*StatType = i;
		*order_bits = 0;
	} else {
		return 0;
	}

	// no order is given - default order applies;
	if ( !q ) {
		return 1;
	}

	// check if one or more orders are given
	r = ++q;
	while ( r ) {
		q = strchr(r, '/');
		if ( q ) 
			*q = 0;
		i = 0;
		while ( order_mode[i].string ) {
			if (  strcasecmp(order_mode[i].string, r ) == 0 )
				break;
			i++;
		}
		if ( order_mode[i].string ) {
			*order_bits |= order_mode[i].val;
		} else 
			return 0;

		if ( !q ) {
			return 1;
		}

		r = ++q;
	}

	return 0;

} // End of ParseStatString

int SetStat_DefaultOrder(char *order) {
int order_index;

	order_index = 0;
	while ( order_mode[order_index].string ) {
		if (  strcasecmp(order_mode[order_index].string, order ) == 0 )
			break;
		order_index++;
	}
	if ( !order_mode[order_index].string )
		return 0;

	DefaultOrder = order_mode[order_index].val;
	return 1;

} // End of SetStat_DefaultOrder

static inline FlowTableRecord_t *hash_lookup_FlowTable(uint32_t *index_cache, uint8_t proto,
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

static inline StatRecord_t *stat_hash_lookup(uint32_t addr, int hash_num) {
uint32_t		index;
StatRecord_t	*record;

	index = addr & StatTable[hash_num].IndexMask;
	if ( StatTable[hash_num].bucket[index] == NULL )
		return NULL;

	record = StatTable[hash_num].bucket[index];
	while ( record && ( record->stat_key != addr ) ) {
		record = record->next;
	}
	return record;

} // End of stat_hash_lookup

static void Expand_FlowTable_Blocks(void) {

	if ( FlowTable.NumBlocks >= FlowTable.MaxBlocks ) {
		FlowTable.MaxBlocks += MaxMemBlocks;
		FlowTable.memblock = (FlowTableRecord_t **)realloc(FlowTable.memblock,
						FlowTable.MaxBlocks * sizeof(FlowTableRecord_t *));
		if ( !FlowTable.memblock ) {
			perror("Expand_FlowTable_Blocks Memory error");
			exit(250);
		}
	}
	FlowTable.memblock[FlowTable.NumBlocks] = 
			(FlowTableRecord_t *)calloc(FlowTable.Prealloc, sizeof(FlowTableRecord_t));

	if ( !FlowTable.memblock[FlowTable.NumBlocks] ) {
		perror("Expand_FlowTable_Blocks Memory error");
		exit(250);
	}
	FlowTable.NextBlock = FlowTable.NumBlocks++;
	FlowTable.NextElem  = 0;

} // End of Expand_FlowTable_Blocks

static void Expand_StatTable_Blocks(int hash_num) {

	if ( StatTable[hash_num].NumBlocks >= StatTable[hash_num].MaxBlocks ) {
		StatTable[hash_num].MaxBlocks += MaxMemBlocks;
		StatTable[hash_num].memblock = (StatRecord_t **)realloc(StatTable[hash_num].memblock,
						StatTable[hash_num].MaxBlocks * sizeof(StatRecord_t *));
		if ( !StatTable[hash_num].memblock ) {
			perror("Expand_StatTable_Blocks Memory error");
			exit(250);
		}
	}
	StatTable[hash_num].memblock[StatTable[hash_num].NumBlocks] = 
			(StatRecord_t *)calloc(StatTable[hash_num].Prealloc, sizeof(StatRecord_t));

	if ( !StatTable[hash_num].memblock[StatTable[hash_num].NumBlocks] ) {
		perror("Expand_StatTable_Blocks Memory error");
		exit(250);
	}
	StatTable[hash_num].NextBlock = StatTable[hash_num].NumBlocks++;
	StatTable[hash_num].NextElem  = 0;

} // End of Expand_StatTable_Blocks

inline static FlowTableRecord_t *hash_insert_FlowTable(uint32_t index_cache,
				uint32_t addr, uint32_t dstaddr, uint16_t port, uint16_t dstport) {
FlowTableRecord_t	*record;

	if ( FlowTable.NextElem >= FlowTable.Prealloc )
		Expand_FlowTable_Blocks();

	record = &(FlowTable.memblock[FlowTable.NextBlock][FlowTable.NextElem]);
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

void InsertFlow(flow_record_t *flow_record) {
FlowTableRecord_t	*record;

	if ( FlowTable.NextElem >= FlowTable.Prealloc )
		Expand_FlowTable_Blocks();

	record = &(FlowTable.memblock[FlowTable.NextBlock][FlowTable.NextElem]);
	FlowTable.NextElem++;

	record->next  			 = NULL;
	record->ip1   			 = flow_record->srcaddr;
	record->ip2   			 = flow_record->dstaddr;
	record->port1 			 = flow_record->srcport;
	record->port2 			 = flow_record->dstport;
	record->counter[BYTES] 	 = flow_record->dOctets;
	record->counter[PACKETS] = flow_record->dPkts;
	record->first	   		 = flow_record->First;
	record->msec_first  	 = flow_record->msec_first;
	record->last	   		 = flow_record->Last;
	record->msec_last   	 = flow_record->msec_last;
	record->proto	   		 = flow_record->prot;
	record->tcp_flags  		 = flow_record->tcp_flags;
	record->tos  			 = flow_record->tos;
	record->counter[FLOWS]	 = 1;

} // End of InsertFlow


inline static StatRecord_t *stat_hash_insert(uint32_t addr, int hash_num) {
uint32_t		index;
StatRecord_t	*record;

	if ( StatTable[hash_num].NextElem >= StatTable[hash_num].Prealloc )
		Expand_StatTable_Blocks(hash_num);

	record = &(StatTable[hash_num].memblock[StatTable[hash_num].NextBlock][StatTable[hash_num].NextElem]);
	StatTable[hash_num].NextElem++;
	record->next     = NULL;
	record->stat_key = addr;

	index = addr & StatTable[hash_num].IndexMask;
	if ( StatTable[hash_num].bucket[index] == NULL ) 
		StatTable[hash_num].bucket[index] = record;
	else
		StatTable[hash_num].bucketcache[index]->next = record;
	StatTable[hash_num].bucketcache[index] = record;
	
	return record;

} // End of stat_hash_insert

int AddStat(flow_header_t *flow_header, flow_record_t *flow_record, int flow_stat, int element_stat ) {
FlowTableRecord_t	*FlowTableRecord;
StatRecord_t		*stat_record;
uint32_t			index_cache, value;
int					j, i;

	if ( flow_stat ) {
		// Update netflow statistics
		FlowTableRecord = hash_lookup_FlowTable(&index_cache, flow_record->prot,
						flow_record->srcaddr, flow_record->dstaddr, flow_record->srcport, flow_record->dstport);
		if ( FlowTableRecord ) {
			FlowTableRecord->counter[BYTES]   += flow_record->dOctets;
			FlowTableRecord->counter[PACKETS] += flow_record->dPkts;

			if ( TimeMsec_CMP(flow_record->First, flow_record->msec_first, FlowTableRecord->first, FlowTableRecord->msec_first) == 2) {
				FlowTableRecord->first = flow_record->First;
				FlowTableRecord->msec_first = flow_record->msec_first;
			}
			if ( TimeMsec_CMP(flow_record->Last, flow_record->msec_last, FlowTableRecord->last, FlowTableRecord->msec_last) == 1) {
				FlowTableRecord->last = flow_record->Last;
				FlowTableRecord->msec_last = flow_record->msec_last;
			}

			FlowTableRecord->counter[FLOWS]++;
	
		} else {
			FlowTableRecord = hash_insert_FlowTable(index_cache, 
							flow_record->srcaddr, flow_record->dstaddr, flow_record->srcport, flow_record->dstport);
			if ( !FlowTableRecord )
				return -1;
	
			FlowTableRecord->counter[BYTES]	  = flow_record->dOctets;
			FlowTableRecord->counter[PACKETS] = flow_record->dPkts;
			FlowTableRecord->first	 		  = flow_record->First;
			FlowTableRecord->msec_first	  	  = flow_record->msec_first;
			FlowTableRecord->last			  = flow_record->Last;
			FlowTableRecord->msec_last		  = flow_record->msec_last;
			FlowTableRecord->tos			  = flow_record->tos;
			FlowTableRecord->tcp_flags		  = flow_record->tcp_flags;
			FlowTableRecord->proto	 		  = flow_record->prot;
			FlowTableRecord->counter[FLOWS]   = 1;
		}
	}

	// Update element statistics
	if ( element_stat ) {
		// for every requested -s stat do
		for ( j=0; j<NumStats; j++ ) {
			int stat   = StatRequest[j].StatType;
			// for the number of elements in this stat type
			for ( i=0; i<StatParameters[stat].num_elem; i++ ) {
				uint32_t offset = StatParameters[stat].element[i].offset;
				uint32_t mask	= StatParameters[stat].element[i].mask;
				uint32_t shift	= StatParameters[stat].element[i].shift;

				value = ((uint32_t *)flow_record)[offset] & mask;
				value = value >> shift;
				stat_record = stat_hash_lookup(value, j);
				if ( stat_record ) {
					stat_record->counter[BYTES] 	+= flow_record->dOctets;
					stat_record->counter[PACKETS]  	+= flow_record->dPkts;
			
					if ( TimeMsec_CMP(flow_record->First, flow_record->msec_first, stat_record->first, stat_record->msec_first) == 2) {
						stat_record->first 		= flow_record->First;
						stat_record->msec_first = flow_record->msec_first;
					}
					if ( TimeMsec_CMP(flow_record->Last, flow_record->msec_last, stat_record->last, stat_record->msec_last) == 1) {
						stat_record->last 		= flow_record->Last;
						stat_record->msec_last 	= flow_record->msec_last;
					}
					stat_record->counter[FLOWS]++;
			
				} else {
					stat_record = stat_hash_insert(value, j);
					if ( !stat_record )
						return -1;
			
					stat_record->counter[BYTES]    	= flow_record->dOctets;
					stat_record->counter[PACKETS]	= flow_record->dPkts;
					stat_record->first    			= flow_record->First;
					stat_record->msec_first 		= flow_record->msec_first;
					stat_record->last				= flow_record->Last;
					stat_record->msec_last			= flow_record->msec_last;
					stat_record->counter[FLOWS] 	= 1;
				}
			} // for the number of elements in this stat type
		} // for every requested -s stat
	} // Update element statistics

	return 0;

} // End of AddStat

static inline void MapRecord(flow_record_t *flow_record, void *record) {
/* This function is needed to normalize the data the feed a flow_record_t for printing */

	flow_record->srcaddr 	= ((FlowTableRecord_t *)record)->ip1;
	flow_record->dstaddr 	= ((FlowTableRecord_t *)record)->ip2;
	flow_record->srcport 	= ((FlowTableRecord_t *)record)->port1;
	flow_record->dstport 	= ((FlowTableRecord_t *)record)->port2;
	flow_record->dOctets 	= ((FlowTableRecord_t *)record)->counter[BYTES];
	flow_record->dPkts   	= ((FlowTableRecord_t *)record)->counter[PACKETS];

	flow_record->First   	= ((FlowTableRecord_t *)record)->first;
	flow_record->msec_first 	= ((FlowTableRecord_t *)record)->msec_first;
	flow_record->Last		= ((FlowTableRecord_t *)record)->last;
	flow_record->msec_last 	= ((FlowTableRecord_t *)record)->msec_last;

	flow_record->prot    	= ((FlowTableRecord_t *)record)->proto;
	flow_record->tcp_flags	= ((FlowTableRecord_t *)record)->tcp_flags;
	flow_record->tos    	= ((FlowTableRecord_t *)record)->tos;

} // End of MapRecord

static void PrintStatLine(StatRecord_t *StatData, int ipconv, int anon) {
char		*str, valstr[32], datestr[64], flows_str[32], byte_str[32], packets_str[32], pps_str[32], bps_str[32];
double		duration;
uint32_t	pps, bps, bpp;
time_t		First;
struct tm	*tbuff;
struct in_addr a;

	if ( ipconv ) {
		a.s_addr = htonl(StatData->stat_key);
		if ( anon ) {
			a.s_addr = anonymize(a.s_addr);
		}
		str = inet_ntoa(a);
		strncpy(valstr, str, 15);
		valstr[15] = 0;
	} else {
		snprintf(valstr, 15, "%u", StatData->stat_key);
		valstr[31] = 0;
	}

	format_number(StatData->counter[FLOWS], flows_str);
	format_number(StatData->counter[PACKETS], packets_str);
	format_number(StatData->counter[BYTES], byte_str);

	duration = StatData->last - StatData->first;
	duration += ((double)StatData->msec_last - (double)StatData->msec_first) / 1000.0;
	
	if ( duration != 0 ) {
		pps = (uint32_t)((double)StatData->counter[PACKETS] / duration);
		bps = (uint32_t)((double)(8 * StatData->counter[BYTES]) / duration);
	} else {
		pps = bps = 0;
	}
	bpp = StatData->counter[BYTES] / StatData->counter[PACKETS];
	format_number(pps, pps_str);
	format_number(bps, bps_str);

	First = StatData->first;
	tbuff = localtime(&First);
	if ( !tbuff ) {
		perror("Error time convert");
		exit(250);
	}
	strftime(datestr, 63, "%Y-%m-%d %H:%M:%S", tbuff);

	printf("%s.%03u %8.3f %15s %8s %8s %8s %8s %8s %5u\n", datestr, StatData->msec_first, duration, 
			valstr, flows_str, packets_str, byte_str, pps_str, bps_str, bpp );

} // End of PrintStatLine

void ReportAggregated(printer_t print_record, uint32_t limitflows, int date_sorted, int anon) {
FlowTableRecord_t	*r;
flow_record_t		flow_record;
SortElement_t 		*SortList;
uint32_t 			i, j, tmp;
uint32_t			maxindex, c;
char				*string;

	c = 0;
	maxindex = ( FlowTable.NextBlock * FlowTable.Prealloc ) + FlowTable.NextElem;
	if ( date_sorted ) {
		// Sort according the date
		SortList = (SortElement_t *)calloc(maxindex+1, sizeof(SortElement_t));

		if ( !SortList ) {
			perror("Can't allocate Top N lists: \n");
			return;
		}

		// preset SortList table - still unsorted
		for ( i=0; i <= FlowTable.IndexMask; i++ ) {
			r = FlowTable.bucket[i];
			// foreach elem in this bucket
			while ( r ) {
				// we want to sort only those flows which pass the packet or byte limits
				if ( byte_limit ) {
					if (( byte_mode == LESS && r->counter[BYTES] >= byte_limit ) ||
						( byte_mode == MORE && r->counter[BYTES]  <= byte_limit ) ) {
						r = r->next;
						continue;
					}
				}
				if ( packet_limit ) {
					if (( packet_mode == LESS && r->counter[PACKETS] >= packet_limit ) ||
						( packet_mode == MORE && r->counter[PACKETS]  <= packet_limit ) ) {
						r = r->next;
						continue;
					}
				}
				
				SortList[c].count  = 1000LL * r->first + r->msec_first;	// sort according the date
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

			flow_record.srcaddr 	= ((FlowTableRecord_t *)(SortList[i].record))->ip1;
			flow_record.dstaddr 	= ((FlowTableRecord_t *)(SortList[i].record))->ip2;
			flow_record.srcport 	= ((FlowTableRecord_t *)(SortList[i].record))->port1;
			flow_record.dstport 	= ((FlowTableRecord_t *)(SortList[i].record))->port2;
			flow_record.dOctets 	= ((FlowTableRecord_t *)(SortList[i].record))->counter[BYTES];
			flow_record.dPkts   	= ((FlowTableRecord_t *)(SortList[i].record))->counter[PACKETS];

			flow_record.First   	= ((FlowTableRecord_t *)(SortList[i].record))->first;
			flow_record.msec_first 	= ((FlowTableRecord_t *)(SortList[i].record))->msec_first;
			flow_record.Last		= ((FlowTableRecord_t *)(SortList[i].record))->last;
			flow_record.msec_last 	= ((FlowTableRecord_t *)(SortList[i].record))->msec_last;

			flow_record.prot    	= ((FlowTableRecord_t *)(SortList[i].record))->proto;
			flow_record.tcp_flags	= ((FlowTableRecord_t *)(SortList[i].record))->tcp_flags;
			flow_record.tos    	= ((FlowTableRecord_t *)(SortList[i].record))->tos;

			print_record((void *)&flow_record, ((FlowTableRecord_t *)(SortList[i].record))->counter[FLOWS], 
							((FlowTableRecord_t *)(SortList[i].record))->counter[PACKETS],
							((FlowTableRecord_t *)(SortList[i].record))->counter[BYTES],
							&string, anon);
			printf("%s\n", string);

		}

	} else {
		// print them as they came
		c = 0;
		for ( i=0; i < FlowTable.NumBlocks; i++ ) {
			tmp = i * FlowTable.Prealloc;
			for ( j=0; j < FlowTable.Prealloc; j++ ) {
				r = &(FlowTable.memblock[i][j]);
				if ( (tmp + j) < maxindex ) {
					if ( limitflows && c >= limitflows )
						return;

					// we want to print only those flows which pass the packet or byte limits
					if ( byte_limit ) {
						if (( byte_mode == LESS && r->counter[BYTES] >= byte_limit ) ||
							( byte_mode == MORE && r->counter[BYTES]  <= byte_limit ) ) {
							continue;
						}
					}
					if ( packet_limit ) {
						if (( packet_mode == LESS && r->counter[PACKETS] >= packet_limit ) ||
							( packet_mode == MORE && r->counter[PACKETS]  <= packet_limit ) ) {
							continue;
						}
					}

					flow_record.srcaddr 	= r->ip1;
					flow_record.dstaddr 	= r->ip2;
					flow_record.srcport 	= r->port1;
					flow_record.dstport 	= r->port2;
					flow_record.dOctets 	= r->counter[BYTES];
					flow_record.dPkts   	= r->counter[PACKETS];
					flow_record.First   	= r->first;
					flow_record.msec_first 	= r->msec_first;
					flow_record.Last	   	= r->last;
					flow_record.msec_last 	= r->msec_last;
					flow_record.prot    	= r->proto;
					flow_record.tcp_flags	= r->tcp_flags;
					flow_record.tos    		= r->tos;

					print_record((void *)&flow_record, r->counter[FLOWS], r->counter[PACKETS], r->counter[BYTES], &string, anon);
					printf("%s\n", string);

					c++;
				}
			}
		}
	}

} // End of ReportAggregated

void ReportStat(char *record_header, printer_t print_record, int topN, int flow_stat, int element_stat, int anon) {
SortElement_t 	*topN_flow_list[NumOrders];
SortElement_t	*topN_element_list;
flow_record_t	flow_record;
uint32_t		numflows, maxindex;
int32_t 		i, j, hash_num, order_index, order_bit;
char			*string;


	if ( flow_stat ) {
		for ( i=0; i<NumOrders; i++ ) {
			topN_flow_list[i] = (SortElement_t *)calloc(topN, sizeof(SortElement_t));
			if ( !topN_flow_list[i] ) {
				perror("Can't allocate TopN listarray: \n");
				return;
			}
		}

		Create_topN_FlowStat(topN_flow_list, flow_stat_order , topN, &numflows);
		printf("Aggregated flows %u\n", numflows);
	
		
		for ( order_index=0; order_index<NumOrders; order_index++ ) {
			order_bit = 1 << order_index;
			if ( flow_stat_order & order_bit ) {
				printf("Top %i flows ordered by %s:\n", topN, order_mode[order_index].string);
				if ( record_header ) 
					printf("%s\n", record_header);
				for ( i=topN-1; i>=0; i--) {
					if ( !topN_flow_list[order_index][i].count )
						break;
		
					MapRecord(&flow_record, topN_flow_list[order_index][i].record);
		
					print_record((void *)&flow_record, 
							((FlowTableRecord_t *)(topN_flow_list[order_index][i].record))->counter[FLOWS], 
							((FlowTableRecord_t *)(topN_flow_list[order_index][i].record))->counter[PACKETS], 
							((FlowTableRecord_t *)(topN_flow_list[order_index][i].record))->counter[BYTES],
							&string, anon);
					printf("%s\n", string);

				}
				printf("\n");
			}
		}

/*
		printf("Top %i flows packet count:\n", topN);
		if ( record_header ) 
			printf("%s\n", record_header);

		for ( i=topN-1; i>=0; i--) {
			if ( !topN_flow_list[PACKETS][i].count )
				break;

			MapRecord(&flow_record, topN_flow_list[PACKETS][i].record);

			print_record((void *)&flow_record, ((FlowTableRecord_t *)(topN_flow_list[PACKETS][i].record))->counter[FLOWS], &string, anon);
			printf("%s\n", string);

		}

		printf("\nTop %i flows byte count:\n", topN);
		if ( record_header ) 
			printf("%s\n", record_header);

		for ( i=topN-1; i>=0; i--) {
			if ( !topN_flow_list[BYTES][i].count )
				break;

			MapRecord(&flow_record, topN_flow_list[BYTES][i].record);

			print_record((void *)&flow_record, ((FlowTableRecord_t *)(topN_flow_list[BYTES][i].record))->counter[FLOWS], &string, anon);
			printf("%s\n", string);

		}
		printf("\n");
*/
	}
	if ( element_stat ) {
		// for every requested -s stat do
		for ( hash_num=0; hash_num<NumStats; hash_num++ ) {
			int stat   = StatRequest[hash_num].StatType;
			int order  = StatRequest[hash_num].order_bits;
			int	ipconv = StatParameters[stat].ipconv;

			for ( order_index=0; order_index<NumOrders; order_index++ ) {
				order_bit = 1 << order_index;
				if ( order & order_bit ) {
					topN_element_list = StatTopN(topN, &numflows, hash_num, order_index);
					printf("Top %i %s ordered by %s:\n", topN, StatParameters[stat].HeaderInfo, order_mode[order_index].string);
					//      2005-07-26 20:08:59.197 1553.730     ss    65255   203435   52.2 M      130   281636   268
					printf("Date first seen         Duration     %s    Flows  Packets    Bytes      pps      bps   bpp\n",
						StatParameters[stat].HeaderInfo);
			
					maxindex = ( StatTable[hash_num].NextBlock * StatTable[hash_num].Prealloc ) + StatTable[hash_num].NextElem;
					j = numflows - topN;
					j = j < 0 ? 0 : j;
					if ( topN == 0 )
						j = 0;
			
					for ( i=numflows-1; i>=j ; i--) {
						if ( !topN_element_list[i].count )
							break;
						PrintStatLine((StatRecord_t *)topN_element_list[i].record, ipconv, anon);
					}
					free((void *)topN_element_list);
					printf("\n");
				}
			} // for every requested order
		} // for every requested -s stat do
	}

} // End of ReportStat

/*
 * Generate the top N lists for packets and bytes in one run
 */
static void Create_topN_FlowStat(SortElement_t **topN_lists, int order, int topN, uint32_t *count ) {
FlowTableRecord_t	*r;
unsigned int		i;
int					order_bit, order_index;
uint64_t	   		c, value;

	c = 0;
	// Iterate through all buckets
	for ( i=0; i <= FlowTable.IndexMask; i++ ) {
		r = FlowTable.bucket[i];
		// foreach elem in this bucket
		while ( r ) {

			// we want to sort only those flows which pass the packet or byte limits
			if ( byte_limit ) {
				if (( byte_mode == LESS && r->counter[BYTES] >= byte_limit ) ||
					( byte_mode == MORE && r->counter[BYTES]  <= byte_limit ) ) {
					r = r->next;
					continue;
				}
			}
			if ( packet_limit ) {
				if (( packet_mode == LESS && r->counter[PACKETS] >= packet_limit ) ||
					( packet_mode == MORE && r->counter[PACKETS]  <= packet_limit ) ) {
					r = r->next;
					continue;
				}
			}

			c++;
			for ( order_index=0; order_index<NumOrders; order_index++ ) {
				order_bit = 1 << order_index;
				if ( order & order_bit ) {
					if ( order_mode[order_index].function ) 
						value  = order_mode[order_index].function((CommonRecord_t *)r);
					else
						value  = r->counter[order_index];
					RankValue(r, value, topN, topN_lists[order_index]);
				}
			}

			// next elem in bucket
			r = r->next;
		} // foreach element
	}
	*count = c;

} // End of Create_topN_FlowStat

void PrintSortedFlows(printer_t print_record, uint32_t limitflows, int anon) {
FlowTableRecord_t	*r;
SortElement_t 		*SortList;
flow_record_t			flow_record;
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
			r = &(FlowTable.memblock[i][j]);
			if ( (tmp + j) < maxindex ) {
				SortList[c].count  = 1000LL * r->first + r->msec_first;	// sort according the date
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

		flow_record.srcaddr 	= r->ip1;
		flow_record.dstaddr 	= r->ip2;
		flow_record.srcport 	= r->port1;
		flow_record.dstport 	= r->port2;
		flow_record.dOctets 	= r->counter[BYTES];
		flow_record.dPkts   	= r->counter[PACKETS];
		flow_record.First   	= r->first;
		flow_record.msec_first 	= r->msec_first;
		flow_record.Last 	  	= r->last;
		flow_record.msec_last  	= r->msec_last;
		flow_record.prot    	= r->proto;
		flow_record.tcp_flags	= r->tcp_flags;
		flow_record.tos    		= r->tos;

		print_record((void *)&flow_record, 1, r->counter[PACKETS], r->counter[BYTES], &string, anon);

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

static SortElement_t *StatTopN(int topN, uint32_t *count, int hash_num, int order ) {
SortElement_t 		*topN_list;
StatRecord_t		*r;
unsigned int		i;
uint32_t	   		c, maxindex;

	maxindex  = ( StatTable[hash_num].NextBlock * StatTable[hash_num].Prealloc ) + StatTable[hash_num].NextElem;
	topN_list = (SortElement_t *)calloc(maxindex+1, sizeof(SortElement_t));	// +1 for heapsort bug

	if ( !topN_list ) {
		perror("Can't allocate Top N lists: \n");
		return NULL;
	}

	// preset topN_list table - still unsorted
	c = 0;
	// Iterate through all buckets
	for ( i=0; i <= StatTable[hash_num].IndexMask; i++ ) {
		r = StatTable[hash_num].bucket[i];
		// foreach elem in this bucket
		while ( r ) {
			// next elem in bucket

			// we want to sort only those flows which pass the packet or byte limits
			if ( byte_limit ) {
				if (( byte_mode == LESS && r->counter[BYTES] >= byte_limit ) ||
					( byte_mode == MORE && r->counter[BYTES]  <= byte_limit ) ) {
					r = r->next;
					continue;
				}
			}
			if ( packet_limit ) {
				if (( packet_mode == LESS && r->counter[PACKETS] >= packet_limit ) ||
					( packet_mode == MORE && r->counter[PACKETS]  <= packet_limit ) ) {
					r = r->next;
					continue;
				}
			}

			if ( order_mode[order].function ) 
				topN_list[c].count  = order_mode[order].function((CommonRecord_t *)r);
			else
				topN_list[c].count  = r->counter[order];

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
	
} // End of StatTopN


static inline void RankValue(FlowTableRecord_t *r, uint64_t val, int topN, SortElement_t *topN_list) {
FlowTableRecord_t	*r1, *r2;
uint64_t	   		c1, c2;
int					j;

	if ( val > (topN_list)[0].count ) {
		/* element value is bigger than smallest value in topN */
		c1 = val;
		r1 = r;
		for (j=topN-1; j>=0; j-- ) {
			if ( c1 > topN_list[j].count ) {
				c2 = topN_list[j].count;
				r2 = topN_list[j].record;
				topN_list[j].count 	= c1;
				topN_list[j].record	= r1;
				c1 = c2; r1 = r2;
			}
		}
	} 

} // End of RankValue

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

