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
 *  $Id: nfstat.c 92 2007-08-24 12:10:24Z peter $
 *
 *  $LastChangedRevision: 92 $
 *	
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "rbtree.h"
#include "nfdump.h"
#include "nffile.h"
#include "nfnet.h"
#include "netflow_v5_v7.h"
#include "nf_common.h"
#include "util.h"
#include "panonymizer.h"
#include "nfstat.h"

struct flow_element_s {
	uint32_t	offset0;
	uint32_t	offset1;	// set in the netflow record block
	uint64_t	mask;		// mask for value in 64bit word
	uint32_t	shift;		// number of bits to shift right to get final value
};

struct StatParameter_s {
	char					*statname;		// name of -s option
	char					*HeaderInfo;	// How to name the field in the output header line
	struct flow_element_s	element[2];		// what element(s) in flow record is used for statistics.
											// need 2 elements to be able to get src/dst stats in one stat record
	uint8_t					num_elem;		// number of elements used. 1 or 2
	uint8_t					ipconv;			// is an IP address: Convert number to readable IP Addr
	uint16_t				aggregate_bits;	// These bits must be set in aggregate mask
} StatParameters[] ={
	// flow record stst
	{ "record",	 "", 			
		{ {0,0, 0},											{0,0,0} },
			1, 0, 0},

	// 9 possible flow element stats 
	{ "srcip",	 "Src IP Addr", 
		{ {OffsetSrcIPv6a, OffsetSrcIPv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, 1, Aggregate_SRCIP},

	{ "dstip",	 "Dst IP Addr", 
		{ {OffsetDstIPv6a, OffsetDstIPv6b, MaskIPv6, 0},	{0,0,0,0} },
			1, 1, Aggregate_DSTIP},

	{ "ip",	 	 "    IP Addr", 
		{ {OffsetSrcIPv6a, OffsetSrcIPv6b, MaskIPv6, 0},	{OffsetDstIPv6a, OffsetDstIPv6b, MaskIPv6} },
			2, 1, Aggregate_SRCIP | Aggregate_DSTIP },

	{ "srcport", "   Src Port", 
		{ {0, OffsetPort, MaskSrcPort, ShiftSrcPort}, 		{0,0,0,0} },
			1, 0, Aggregate_SRCPORT},

	{ "dstport", "   Dst Port", 
		{ {0, OffsetPort, MaskDstPort, ShiftDstPort}, 		{0,0,0,0} },
			1, 0, Aggregate_DSTPORT},

	{ "port", 	 "       Port", 
		{ {0, OffsetPort, MaskSrcPort, ShiftSrcPort}, 		{0, OffsetPort, MaskDstPort, ShiftDstPort}},
			2, 0, Aggregate_SRCPORT | Aggregate_DSTPORT},

	{ "proto", 	 "   Protocol", 
		{ {0, OffsetProto, MaskProto, ShiftProto}, 			{0,0,0,0} },
			1, 0, 0},

	{ "tos", 	 "        Tos", 
		{ {0, OffsetTos, MaskTos, ShiftTos}, 				{0,0,0,0} },
			1, 0, 0},

	{ "srcas",	 "     Src AS", 
		{ {0, OffsetAS, MaskSrcAS, ShiftSrcAS},		  		{0,0,0,0} },
			1, 0, 0},

	{ "dstas",	 "     Dst AS", 
		{ {0, OffsetAS, MaskDstAS, ShiftDstAS},  	  		{0,0,0,0} },
			1, 0, 0},

	{ "as",	 	 "         AS", 
		{ {0, OffsetAS, MaskSrcAS, ShiftSrcAS},  	  		{0, OffsetAS, MaskDstAS, ShiftDstAS} },
			2, 0, 0},

	{ "inif", 	 "   Input If", 
		{ {0, OffsetInOut, MaskInput, ShiftInput}, 			{0,0,0,0} },
			1, 0, 0},

	{ "outif", 	 "  Output If", 
		{ {0, OffsetInOut, MaskOutput, ShiftOutput},		{0,0,0,0} },
			1, 0, 0},

	{ "if", 	 "  In/Out If", 
		{ {0, OffsetInOut, MaskInput, ShiftInput},			{0, OffsetInOut, MaskOutput, ShiftOutput} },
			1, 0, 0},

	{ NULL, 	 NULL, 			
		{ {0,0,0,0},								  		{0,0,0,0} },
			1, 0, 0}
};

static const uint32_t NumOrders = 6;	// Number of Stats in enum StatTypes
// StatType max 32767 
enum StatTypes { FLOWS = 0, PACKETS, BYTES, PPS, BPS, BPP };

#define MaxStats 16
struct StatRequest_s {
	uint16_t	order_bits;		// bits 0: flows 1: packets 2: bytes 3: pps 4: bps, 5 bpp
	int16_t		StatType;		// value out of enum StatTypes
	uint8_t		order_proto;	// protocol separated statistics
} StatRequest[MaxStats];		// This number should do it for a single run

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


static uint32_t	byte_limit, packet_limit;
static int byte_mode, packet_mode;
enum { NONE, LESS, MORE };

#define MaxMemBlocks	256

/* function prototypes */
static int ParseStatString(char *str, int16_t	*StatType, uint16_t *order_bits, int *flow_record_stat, uint16_t *order_proto);

static inline FlowTableRecord_t *hash_lookup_FlowTable(uint32_t *index_cache, master_record_t *flow_record);

static inline FlowTableRecord_t *hash_insert_FlowTable(uint32_t index_cache, master_record_t *flow_record);

static inline StatRecord_t *stat_hash_lookup(uint64_t *value, uint8_t prot, int hash_num);

static inline StatRecord_t *stat_hash_insert(uint64_t *value, uint8_t prot, int hash_num);

static void Expand_FlowTable_Blocks(void);

static void Expand_StatTable_Blocks(int hash_num);

static inline void MapRecord(master_record_t *flow_record, void *record);

static void PrintStatLine(StatRecord_t *StatData, int ipconv, int anon, int order_proto, int tag);

static void PrintPipeStatLine(StatRecord_t *StatData, int ipconv, int anon, int order_proto, int tag);

static void Create_topN_FlowStat(SortElement_t **topN_lists, int order, int topN, uint32_t *count );

static inline int TimeMsec_CMP(time_t t1, uint16_t offset1, time_t t2, uint16_t offset2 );

// static SortElement_t *Make_TopN_packets(int topN, uint32_t *count);

// static SortElement_t *Make_TopN_bytes(int topN, uint32_t *count);

static SortElement_t *StatTopN(int topN, uint32_t *count, int hash_num, int order );

static inline void RankValue(FlowTableRecord_t *r, uint64_t val, int topN, SortElement_t *topN_list);

static void heapSort(SortElement_t *SortElement, uint32_t array_size, int topN);

static inline void siftDown(SortElement_t *SortElement, uint32_t root, uint32_t bottom);

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
#define mix64(a,b,c) \
{ \
	a=a-b;  a=a-c;  a=a^(c>>43); \
	b=b-c;  b=b-a;  b=b^(a<<9); \
	c=c-a;  c=c-b;  c=c^(b>>8); \
	a=a-b;  a=a-c;  a=a^(c>>38); \
	b=b-c;  b=b-a;  b=b^(a<<23); \
	c=c-a;  c=c-b;  c=c^(b>>5); \
	a=a-b;  a=a-c;  a=a^(c>>35); \
	b=b-c;  b=b-a;  b=b^(a<<49); \
	c=c-a;  c=c-b;  c=c^(b>>11); \
	a=a-b;  a=a-c;  a=a^(c>>12); \
	b=b-c;  b=b-a;  b=b^(a<<18); \
	c=c-a;  c=c-b;  c=c^(b>>22); \
}

#define mix32(a,b,c) { \
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

static inline int TimeMsec_CMP(time_t t1, uint16_t offset1, time_t t2, uint16_t offset2 ) {
    if ( t1 > t2 )
        return 1;
    if ( t2 > t1 ) 
        return 2;
    // else t1 == t2 - offset is now relevant
    if ( offset1 > offset2 )
        return 1;
    if ( offset2 > offset1 )
        return 2;
    else
        // both times are the same
        return 0;
} // End of TimeMsec_CMP


void SetLimits(int stat, char *packet_limit_string, char *byte_limit_string ) {
char 		*s, c;
uint32_t	len,scale;

	if ( ( stat == 0 ) && ( packet_limit_string || byte_limit_string )) {
		fprintf(stderr,"Options -l and -L do not make sense for plain packet dumps.\n");
		fprintf(stderr,"Use -l and -L together with -s -S or -a.\n");
		fprintf(stderr,"Use netflow filter syntax to limit the number of packets and bytes in netflow records.\n");
		exit(250);
	}
	packet_limit = byte_limit = 0;
	if ( packet_limit_string ) {
		switch ( packet_limit_string[0] ) {
			case '-':
				packet_mode = LESS;
				s = &packet_limit_string[1];
				break;
			case '+':
				packet_mode = MORE;
				s = &packet_limit_string[1];
				break;
			default:
				if ( !isdigit((int)packet_limit_string[0])) {
					fprintf(stderr,"Can't understand '%s'\n", packet_limit_string);
					exit(250);
				}
				packet_mode = MORE;
				s = packet_limit_string;
		}
		len = strlen(packet_limit_string);
		c = packet_limit_string[len-1];
		switch ( c ) {
			case 'B':
			case 'b':
				scale = 1;
				break;
			case 'K':
			case 'k':
				scale = 1024;
				break;
			case 'M':
			case 'm':
				scale = 1024 * 1024;
				break;
			case 'G':
			case 'g':
				scale = 1024 * 1024 * 1024;
				break;
			default:
				scale = 1;
				if ( isalpha((int)c) ) {
					fprintf(stderr,"Can't understand '%c' in '%s'\n", c, packet_limit_string);
					exit(250);
				}
		}
		packet_limit = atol(s) * scale;
	}

	if ( byte_limit_string ) {
		switch ( byte_limit_string[0] ) {
			case '-':
				byte_mode = LESS;
				s = &byte_limit_string[1];
				break;
			case '+':
				byte_mode = MORE;
				s = &byte_limit_string[1];
				break;
			default:
				if ( !isdigit((int)byte_limit_string[0])) {
					fprintf(stderr,"Can't understand '%s'\n", byte_limit_string);
					exit(250);
				}
				byte_mode = MORE;
				s = byte_limit_string;
		}
		len = strlen(byte_limit_string);
		c = byte_limit_string[len-1];
		switch ( c ) {
			case 'B':
			case 'b':
				scale = 1;
				break;
			case 'K':
			case 'k':
				scale = 1024;
				break;
			case 'M':
			case 'm':
				scale = 1024 * 1024;
				break;
			case 'G':
			case 'g':
				scale = 1024 * 1024 * 1024;
				break;
			default:
				if ( isalpha((int)c) ) {
					fprintf(stderr,"Can't understand '%c' in '%s'\n", c, byte_limit_string);
					exit(250);
				}
				scale = 1;
		}
		byte_limit = atol(s) * scale;
	}

	if ( byte_limit )
		printf("Byte limit: %c %u bytes\n", byte_mode == LESS ? '<' : '>', byte_limit);

	if ( packet_limit )
		printf("Packet limit: %c %u packets\n", packet_mode == LESS ? '<' : '>', packet_limit);


} // End of SetLimits


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

char *VerifyStat(uint16_t Aggregate_Bits) {
int16_t i, StatType;

	for ( i=0; i<NumStats ; i++ ) {
		StatType = StatRequest[i].StatType;
		if ( (StatParameters[StatType].aggregate_bits & Aggregate_Bits) != StatParameters[StatType].aggregate_bits ) {
			return StatParameters[StatType].statname;
		}
	}
	return NULL;

} // End of VerifyStat

int SetStat(char *str, int *element_stat, int *flow_stat) {
int			flow_record_stat = 0;
int16_t 	StatType    = 0;
uint16_t	order_bits  = 0;
uint16_t	order_proto = 0;

	if ( NumStats == MaxStats ) {
		fprintf(stderr, "Too many stat options! Stats are limited to %i stats per single run!\n", MaxStats);
		return 0;
	}
	if ( ParseStatString(str, &StatType, &order_bits, &flow_record_stat, &order_proto) ) {
		if ( flow_record_stat ) {
			flow_stat_order = order_bits;
			*flow_stat = 1;
		} else {
			StatRequest[NumStats].StatType 	  = StatType;
			StatRequest[NumStats].order_bits  = order_bits;
			StatRequest[NumStats].order_proto = order_proto;
			NumStats++;
			*element_stat = 1;
		}
		return 1;
	} else {
		fprintf(stderr, "Unknown stat: '%s'!\n", str);
		return 0;
	}

} // End of SetStat

static int ParseStatString(char *str, int16_t	*StatType, uint16_t *order_bits, int *flow_record_stat, uint16_t *order_proto) {
char	*s, *p, *q, *r;
int i=0;

	if ( NumStats >= MaxStats )
		return 0;

	s = strdup(str);
	q = strchr(s, '/');
	if ( q ) 
		*q = 0;

	*order_proto = 0;
	p = strchr(s, ':');
	if ( p ) {
		*p = 0;
		*order_proto = 1;
	}

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
		if ( strncasecmp(StatParameters[i].statname, "proto", 16) == 0 ) 
			*order_proto = 1;
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

static inline FlowTableRecord_t *hash_lookup_FlowTable(uint32_t *index_cache, master_record_t *flow_record) {
// uint64_t			index, a1, a2;
uint32_t			index, a1, a2, as;
FlowTableRecord_t	*record;

	index = (uint32_t)flow_record->srcport << 16 | (uint32_t)flow_record->dstport;
	as = (uint32_t)flow_record->srcas << 16 | (uint32_t)flow_record->dstas;
	a1 = flow_record->v4.srcaddr;
	a2 = flow_record->v4.dstaddr;
	mix32(a1, a2, index);

	// a1 = flow_record->v6.srcaddr[1];
	// a2 = flow_record->v6.dstaddr[1];
	// mix64(a1, a2, index);

	index = (as ^ ( index >> ( 32 - FlowTable.NumBits ))) & FlowTable.IndexMask;

	*index_cache = index;

	if ( FlowTable.bucket[index] == NULL )
		return NULL;

	record = FlowTable.bucket[index];
	while ( record ) {
		if ( record->srcport == flow_record->srcport && record->dstport == flow_record->dstport &&
		   	record->prot == flow_record->prot &&
			record->ip.v6.srcaddr[1] == flow_record->v6.srcaddr[1] && record->ip.v6.dstaddr[1] == flow_record->v6.dstaddr[1] && 
			record->ip.v6.srcaddr[0] == flow_record->v6.srcaddr[0] && record->ip.v6.dstaddr[0] == flow_record->v6.dstaddr[0] &&
			record->srcas == flow_record->srcas && record->dstas == flow_record->dstas )
			return record;
		record = record->next;
	}
	return NULL;

} // End of hash_lookup_FlowTable

static inline StatRecord_t *stat_hash_lookup(uint64_t *value, uint8_t prot, int hash_num) {
uint32_t		index;
StatRecord_t	*record;

	index = value[1] & StatTable[hash_num].IndexMask;

	if ( StatTable[hash_num].bucket[index] == NULL )
		return NULL;

	record = StatTable[hash_num].bucket[index];
	if ( StatRequest[hash_num].order_proto ) {
		while ( record && ( record->stat_key[1] != value[1] || record->stat_key[0] != value[0] || prot != record->prot ) ) {
			record = record->next;
		}
	} else {
		while ( record && ( record->stat_key[1] != value[1] || record->stat_key[0] != value[0] ) ) {
			record = record->next;
		}
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

inline static FlowTableRecord_t *hash_insert_FlowTable(uint32_t index_cache, master_record_t *flow_record) {
FlowTableRecord_t	*record;

	if ( FlowTable.NextElem >= FlowTable.Prealloc )
		Expand_FlowTable_Blocks();

	record = &(FlowTable.memblock[FlowTable.NextBlock][FlowTable.NextElem]);
	FlowTable.NextElem++;
	record->next  	= NULL;
	record->prot	= flow_record->prot;
	record->srcport = flow_record->srcport;
	record->dstport = flow_record->dstport;
	record->srcas   = flow_record->srcas;
	record->dstas   = flow_record->dstas;
	record->ip.v6.srcaddr[0] = flow_record->v6.srcaddr[0];
	record->ip.v6.srcaddr[1] = flow_record->v6.srcaddr[1];
	record->ip.v6.dstaddr[0] = flow_record->v6.dstaddr[0];
	record->ip.v6.dstaddr[1] = flow_record->v6.dstaddr[1];

	if ( FlowTable.bucket[index_cache] == NULL ) 
		FlowTable.bucket[index_cache] = record;
	else 
		FlowTable.bucketcache[index_cache]->next = record;
	FlowTable.bucketcache[index_cache] = record;

	return record;

} // End of hash_insert_FlowTable

void InsertFlow(master_record_t *flow_record) {
FlowTableRecord_t	*record;

	if ( FlowTable.NextElem >= FlowTable.Prealloc )
		Expand_FlowTable_Blocks();

	record = &(FlowTable.memblock[FlowTable.NextBlock][FlowTable.NextElem]);
	FlowTable.NextElem++;

	record->next  			 = NULL;
	record->ip.v6.srcaddr[0] = flow_record->v6.srcaddr[0];
	record->ip.v6.srcaddr[1] = flow_record->v6.srcaddr[1];
	record->ip.v6.dstaddr[0] = flow_record->v6.dstaddr[0];
	record->ip.v6.dstaddr[1] = flow_record->v6.dstaddr[1];
	record->srcport 		 = flow_record->srcport;
	record->dstport 		 = flow_record->dstport;
	record->counter[BYTES] 	 = flow_record->dOctets;
	record->counter[PACKETS] = flow_record->dPkts;
	record->first	   		 = flow_record->first;
	record->msec_first  	 = flow_record->msec_first;
	record->last	   		 = flow_record->last;
	record->msec_last   	 = flow_record->msec_last;
	record->prot	   		 = flow_record->prot;
	record->tcp_flags  		 = flow_record->tcp_flags;
	record->tos  			 = flow_record->tos;
	record->srcas  			 = flow_record->srcas;
	record->dstas  			 = flow_record->dstas;
	record->input  			 = flow_record->input;
	record->output 			 = flow_record->output;
	record->counter[FLOWS]	 = 1;

} // End of InsertFlow


static inline StatRecord_t *stat_hash_insert(uint64_t *value, uint8_t prot, int hash_num) {
uint32_t		index;
StatRecord_t	*record;

	if ( StatTable[hash_num].NextElem >= StatTable[hash_num].Prealloc )
		Expand_StatTable_Blocks(hash_num);

	record = &(StatTable[hash_num].memblock[StatTable[hash_num].NextBlock][StatTable[hash_num].NextElem]);
	StatTable[hash_num].NextElem++;
	record->next     	= NULL;
	record->stat_key[0] = value[0];
	record->stat_key[1] = value[1];
	record->prot		= prot;

	index = value[1] & StatTable[hash_num].IndexMask;
	if ( StatTable[hash_num].bucket[index] == NULL ) 
		StatTable[hash_num].bucket[index] = record;
	else
		StatTable[hash_num].bucketcache[index]->next = record;
	StatTable[hash_num].bucketcache[index] = record;
	
	return record;

} // End of stat_hash_insert

int AddStat(data_block_header_t *flow_header, master_record_t *flow_record, int flow_stat, int element_stat,
			int aggregate, uint64_t *AggregateMasks ) {
FlowTableRecord_t	*FlowTableRecord;
StatRecord_t		*stat_record;
uint32_t			index_cache; 
uint64_t			value[2];
int					j, i;

	// Update element statistics
	if ( element_stat ) {
		// for every requested -s stat do
		for ( j=0; j<NumStats; j++ ) {
			int stat   = StatRequest[j].StatType;
			// for the number of elements in this stat type
			for ( i=0; i<StatParameters[stat].num_elem; i++ ) {
				uint32_t offset = StatParameters[stat].element[i].offset1;
				uint64_t mask	= StatParameters[stat].element[i].mask;
				uint32_t shift	= StatParameters[stat].element[i].shift;

				value[1] = (((uint64_t *)flow_record)[offset] & mask) >> shift;
				offset = StatParameters[stat].element[i].offset0;
				value[0] = offset ? ((uint64_t *)flow_record)[offset] : 0;

				stat_record = stat_hash_lookup(value, flow_record->prot, j);
				if ( stat_record ) {
					stat_record->counter[BYTES] 	+= flow_record->dOctets;
					stat_record->counter[PACKETS]  	+= flow_record->dPkts;
			
					if ( TimeMsec_CMP(flow_record->first, flow_record->msec_first, stat_record->first, stat_record->msec_first) == 2) {
						stat_record->first 		= flow_record->first;
						stat_record->msec_first = flow_record->msec_first;
					}
					if ( TimeMsec_CMP(flow_record->last, flow_record->msec_last, stat_record->last, stat_record->msec_last) == 1) {
						stat_record->last 		= flow_record->last;
						stat_record->msec_last 	= flow_record->msec_last;
					}
					stat_record->counter[FLOWS]++;
			
				} else {
					stat_record = stat_hash_insert(value, flow_record->prot, j);
					if ( !stat_record )
						return -1;
			
					stat_record->counter[BYTES]    	= flow_record->dOctets;
					stat_record->counter[PACKETS]	= flow_record->dPkts;
					stat_record->first    			= flow_record->first;
					stat_record->msec_first 		= flow_record->msec_first;
					stat_record->last				= flow_record->last;
					stat_record->msec_last			= flow_record->msec_last;
					stat_record->record_flags		= flow_record->flags & 0x1;
					stat_record->counter[FLOWS] 	= 1;
					/* 
					 * srcas, dstas, inout and output interface: these values are assumed to be constant
					 * and are set when this flow is seen the first time
					 */
				}
			} // for the number of elements in this stat type
		} // for every requested -s stat
	} // Update element statistics

	if ( flow_stat ) {

		// mask record for proper aggregation
		if ( aggregate ) {
			uint64_t	*array64 = (uint64_t *)flow_record;
			// mask ports
			array64[3] &= AggregateMasks[0];
			// mask IP addresses
			array64[5] &= AggregateMasks[1];
			array64[6] &= AggregateMasks[2];
			array64[7] &= AggregateMasks[3];
			array64[8] &= AggregateMasks[4];
			// mask AS numbers
			array64[4] &= AggregateMasks[5];
			// mask protocol
			array64[2] &= AggregateMasks[6];
		}

		// Update netflow statistics
		FlowTableRecord = hash_lookup_FlowTable(&index_cache, flow_record);
		if ( FlowTableRecord ) {
			FlowTableRecord->counter[BYTES]   += flow_record->dOctets;
			FlowTableRecord->counter[PACKETS] += flow_record->dPkts;

			if ( TimeMsec_CMP(flow_record->first, flow_record->msec_first, FlowTableRecord->first, FlowTableRecord->msec_first) == 2) {
				FlowTableRecord->first = flow_record->first;
				FlowTableRecord->msec_first = flow_record->msec_first;
			}
			if ( TimeMsec_CMP(flow_record->last, flow_record->msec_last, FlowTableRecord->last, FlowTableRecord->msec_last) == 1) {
				FlowTableRecord->last = flow_record->last;
				FlowTableRecord->msec_last = flow_record->msec_last;
			}

			FlowTableRecord->counter[FLOWS]++;

			FlowTableRecord->tcp_flags		  |= flow_record->tcp_flags;
			if ( FlowTableRecord->tos != flow_record->tos ) 
				 FlowTableRecord->tos = 0;
			if ( FlowTableRecord->input != flow_record->input ) 
				FlowTableRecord->input = 0;
			if ( FlowTableRecord->output != flow_record->output ) 
				FlowTableRecord->output = 0;
	
		} else {
			FlowTableRecord = hash_insert_FlowTable(index_cache, flow_record);
			if ( !FlowTableRecord )
				return -1;
	
			FlowTableRecord->record_flags	  = flow_record->flags & 1LL;
			FlowTableRecord->first	 		  = flow_record->first;
			FlowTableRecord->msec_first	  	  = flow_record->msec_first;
			FlowTableRecord->last			  = flow_record->last;
			FlowTableRecord->msec_last		  = flow_record->msec_last;
			FlowTableRecord->tcp_flags		  = flow_record->tcp_flags;
			FlowTableRecord->tos			  = flow_record->tos;
			FlowTableRecord->input			  = flow_record->input;
			FlowTableRecord->output			  = flow_record->output;
			FlowTableRecord->counter[BYTES]	  = flow_record->dOctets;
			FlowTableRecord->counter[PACKETS] = flow_record->dPkts;
			FlowTableRecord->counter[FLOWS]   = 1;
		}
	}


	return 0;

} // End of AddStat

static inline void MapRecord(master_record_t *flow_record, void *record) {
/* This function normalizes the data for printing */

	flow_record->flags = ((FlowTableRecord_t *)record)->record_flags;

	flow_record->v6.srcaddr[0] = ((FlowTableRecord_t *)record)->ip.v6.srcaddr[0];
	flow_record->v6.srcaddr[1] = ((FlowTableRecord_t *)record)->ip.v6.srcaddr[1];
	flow_record->v6.dstaddr[0] = ((FlowTableRecord_t *)record)->ip.v6.dstaddr[0];
	flow_record->v6.dstaddr[1] = ((FlowTableRecord_t *)record)->ip.v6.dstaddr[1];
	flow_record->srcport 	= ((FlowTableRecord_t *)record)->srcport;
	flow_record->dstport 	= ((FlowTableRecord_t *)record)->dstport;
	flow_record->dOctets 	= ((FlowTableRecord_t *)record)->counter[BYTES];
	flow_record->dPkts   	= ((FlowTableRecord_t *)record)->counter[PACKETS];

	flow_record->first   	= ((FlowTableRecord_t *)record)->first;
	flow_record->msec_first	= ((FlowTableRecord_t *)record)->msec_first;
	flow_record->last		= ((FlowTableRecord_t *)record)->last;
	flow_record->msec_last 	= ((FlowTableRecord_t *)record)->msec_last;

	flow_record->prot    	= ((FlowTableRecord_t *)record)->prot;
	flow_record->tcp_flags	= ((FlowTableRecord_t *)record)->tcp_flags;
	flow_record->tos    	= ((FlowTableRecord_t *)record)->tos;

	flow_record->srcas    	= ((FlowTableRecord_t *)record)->srcas;
	flow_record->dstas    	= ((FlowTableRecord_t *)record)->dstas;
	flow_record->input    	= ((FlowTableRecord_t *)record)->input;
	flow_record->output    	= ((FlowTableRecord_t *)record)->output;

} // End of MapRecord

static void PrintStatLine(StatRecord_t *StatData, int ipconv, int anon, int order_proto, int tag) {
char		proto[16], valstr[40], datestr[64], flows_str[32], byte_str[32], packets_str[32], pps_str[32], bps_str[32];
char tag_string[2];
double		duration;
uint32_t	pps, bps, bpp;
time_t		first;
struct tm	*tbuff;

	tag_string[0] = '\0';
	tag_string[1] = '\0';
	if ( ipconv ) {
		tag_string[0] = tag ? TAG_CHAR : '\0';
		if ( (StatData->record_flags & 0x1) != 0 ) { // IPv6
			if ( anon ) {
				uint64_t anon_ip[2];
				anonymize_v6(StatData->stat_key, anon_ip);
				StatData->stat_key[0] = anon_ip[0];
				StatData->stat_key[1] = anon_ip[1];
			}
			StatData->stat_key[0] = htonll(StatData->stat_key[0]);
			StatData->stat_key[1] = htonll(StatData->stat_key[1]);
			inet_ntop(AF_INET6, StatData->stat_key, valstr, sizeof(valstr));
			if ( ! Getv6Mode() )
				condense_v6(valstr);

		} else {	// IPv4
			uint32_t	ipv4 = StatData->stat_key[1];
			if ( anon ) {
				ipv4 = anonymize(ipv4);
			}
			ipv4 = htonl(ipv4);
			inet_ntop(AF_INET, &ipv4, valstr, sizeof(valstr));
		}
	} else {
		snprintf(valstr, 40, "%llu", (unsigned long long)StatData->stat_key[1]);
	}
	valstr[39] = 0;

	format_number(StatData->counter[FLOWS], flows_str, FIXED_WIDTH);
	format_number(StatData->counter[PACKETS], packets_str, FIXED_WIDTH);
	format_number(StatData->counter[BYTES], byte_str, FIXED_WIDTH);

	duration = StatData->last - StatData->first;
	duration += ((double)StatData->msec_last - (double)StatData->msec_first) / 1000.0;
	
	if ( duration != 0 ) {
		pps = (uint32_t)((double)StatData->counter[PACKETS] / duration);
		bps = (uint32_t)((double)(8 * StatData->counter[BYTES]) / duration);
	} else {
		pps = bps = 0;
	}
	bpp = StatData->counter[BYTES] / StatData->counter[PACKETS];
	format_number(pps, pps_str, FIXED_WIDTH);
	format_number(bps, bps_str, FIXED_WIDTH);

	first = StatData->first;
	tbuff = localtime(&first);
	if ( !tbuff ) {
		perror("Error time convert");
		exit(250);
	}
	strftime(datestr, 63, "%Y-%m-%d %H:%M:%S", tbuff);

	if ( order_proto ) {
		Proto_string(StatData->prot, proto);
	} else {
		snprintf(proto, 15, "any  ");
		proto[15] = 0;
	}

	if ( Getv6Mode() && ipconv )
		printf("%s.%03u %9.3f %s %s%39s %8s %8s %8s %8s %8s %5u\n", datestr, StatData->msec_first, duration, proto,
				tag_string, valstr, flows_str, packets_str, byte_str, pps_str, bps_str, bpp );
	else
		printf("%s.%03u %9.3f %s %s%16s %8s %8s %8s %8s %8s %5u\n", datestr, StatData->msec_first, duration, proto,
				tag_string, valstr, flows_str, packets_str, byte_str, pps_str, bps_str, bpp );

} // End of PrintStatLine

static void PrintPipeStatLine(StatRecord_t *StatData, int ipconv, int anon, int order_proto, int tag) {
double		duration;
uint32_t	pps, bps, bpp;
uint32_t	sa[4];
int			af;

	sa[0] = sa[1] = sa[2] = sa[3] = 0;
	af = AF_UNSPEC;
	if ( ipconv ) {
		if ( (StatData->record_flags & 0x1) != 0 ) { // IPv6
			if ( anon ) {
				uint64_t anon_ip[2];
				anonymize_v6(StatData->stat_key, anon_ip);
				StatData->stat_key[0] = anon_ip[0];
				StatData->stat_key[1] = anon_ip[1];
			}
			StatData->stat_key[0] = htonll(StatData->stat_key[0]);
			StatData->stat_key[1] = htonll(StatData->stat_key[1]);
			af = PF_INET6;

		} else {	// IPv4
			uint32_t	ipv4 = StatData->stat_key[1];
			if ( anon ) {
				StatData->stat_key[1] = anonymize(ipv4);
			}
			af = PF_INET;
		}
		// Make sure Endian does not screw us up
    	sa[0] = ( StatData->stat_key[0] >> 32 ) & 0xffffffffLL;
    	sa[1] = StatData->stat_key[0] & 0xffffffffLL;
    	sa[2] = ( StatData->stat_key[1] >> 32 ) & 0xffffffffLL;
    	sa[3] = StatData->stat_key[1] & 0xffffffffLL;
	} 
	duration = StatData->last - StatData->first;
	duration += ((double)StatData->msec_last - (double)StatData->msec_first) / 1000.0;
	
	if ( duration != 0 ) {
		pps = (uint32_t)((double)StatData->counter[PACKETS] / duration);
		bps = (uint32_t)((double)(8 * StatData->counter[BYTES]) / duration);
	} else {
		pps = bps = 0;
	}
	bpp = StatData->counter[BYTES] / StatData->counter[PACKETS];

	if ( !order_proto ) {
		StatData->prot = 0;
	}

	if ( ipconv )
		printf("%i|%u|%u|%u|%u|%u|%u|%u|%u|%u|%llu|%llu|%llu|%u|%u|%u\n",
				af, StatData->first, StatData->msec_first ,StatData->last, StatData->msec_last, StatData->prot, 
				sa[0], sa[1], sa[2], sa[3], StatData->counter[FLOWS], StatData->counter[PACKETS], 
				StatData->counter[BYTES], pps, bps, bpp);
	else
		printf("%i|%u|%u|%u|%u|%u|%llu|%llu|%llu|%llu|%u|%u|%u\n",
				af, StatData->first, StatData->msec_first ,StatData->last, StatData->msec_last, StatData->prot, 
				StatData->stat_key[1], StatData->counter[FLOWS], StatData->counter[PACKETS], 
				StatData->counter[BYTES], pps, bps, bpp);

} // End of PrintPipeStatLine


void ReportAggregated(printer_t print_record, uint32_t limitflows, int date_sorted, int anon, int tag) {
FlowTableRecord_t	*r;
master_record_t		flow_record;
SortElement_t 		*SortList;
uint32_t 			i, j, tmp;
uint32_t			maxindex, c;
char				*string;

	c = 0;
	flow_record.flags = 0;

	maxindex = ( FlowTable.NextBlock * FlowTable.Prealloc ) + FlowTable.NextElem;
	if ( date_sorted ) {
		// Sort according the date
		SortList = (SortElement_t *)calloc(maxindex, sizeof(SortElement_t));

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

		if ( c >= 2 )
 			heapSort(SortList, c, 0);

		if ( limitflows && limitflows < maxindex )
			maxindex = limitflows;
		for ( i = 0; i < maxindex; i++ ) {

			flow_record.flags = ((FlowTableRecord_t *)(SortList[i].record))->record_flags;

			flow_record.v6.srcaddr[0] = ((FlowTableRecord_t *)(SortList[i].record))->ip.v6.srcaddr[0];
			flow_record.v6.srcaddr[1] = ((FlowTableRecord_t *)(SortList[i].record))->ip.v6.srcaddr[1];
			flow_record.v6.dstaddr[0] = ((FlowTableRecord_t *)(SortList[i].record))->ip.v6.dstaddr[0];
			flow_record.v6.dstaddr[1] = ((FlowTableRecord_t *)(SortList[i].record))->ip.v6.dstaddr[1];
			flow_record.srcport 	  = ((FlowTableRecord_t *)(SortList[i].record))->srcport;
			flow_record.dstport 	  = ((FlowTableRecord_t *)(SortList[i].record))->dstport;
			flow_record.dOctets 	  = ((FlowTableRecord_t *)(SortList[i].record))->counter[BYTES];
			flow_record.dPkts   	  = ((FlowTableRecord_t *)(SortList[i].record))->counter[PACKETS];

			flow_record.first   	  = ((FlowTableRecord_t *)(SortList[i].record))->first;
			flow_record.msec_first 	  = ((FlowTableRecord_t *)(SortList[i].record))->msec_first;
			flow_record.last		  = ((FlowTableRecord_t *)(SortList[i].record))->last;
			flow_record.msec_last 	  = ((FlowTableRecord_t *)(SortList[i].record))->msec_last;

			flow_record.prot    	  = ((FlowTableRecord_t *)(SortList[i].record))->prot;
			flow_record.tcp_flags	  = ((FlowTableRecord_t *)(SortList[i].record))->tcp_flags;
			flow_record.tos    		  = ((FlowTableRecord_t *)(SortList[i].record))->tos;

			flow_record.srcas    	  = ((FlowTableRecord_t *)(SortList[i].record))->srcas;
			flow_record.dstas    	  = ((FlowTableRecord_t *)(SortList[i].record))->dstas;
			flow_record.input    	  = ((FlowTableRecord_t *)(SortList[i].record))->input;
			flow_record.output    	  = ((FlowTableRecord_t *)(SortList[i].record))->output;

			print_record((void *)&flow_record, ((FlowTableRecord_t *)(SortList[i].record))->counter[FLOWS], &string, anon, tag);
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

					flow_record.flags = r->record_flags;
					flow_record.v6.srcaddr[0] = r->ip.v6.srcaddr[0];
					flow_record.v6.srcaddr[1] = r->ip.v6.srcaddr[1];
					flow_record.v6.dstaddr[0] = r->ip.v6.dstaddr[0];
					flow_record.v6.dstaddr[1] = r->ip.v6.dstaddr[1];
					flow_record.srcport 	  = r->srcport;
					flow_record.dstport 	  = r->dstport;
					flow_record.dOctets 	  = r->counter[BYTES];
					flow_record.dPkts   	  = r->counter[PACKETS];
					flow_record.first     	  = r->first;
					flow_record.msec_first 	  = r->msec_first;
					flow_record.last	   	  = r->last;
					flow_record.msec_last 	  = r->msec_last;
					flow_record.prot    	  = r->prot;
					flow_record.tcp_flags	  = r->tcp_flags;
					flow_record.tos    		  = r->tos;
					flow_record.srcas 	  	  = r->srcas;
					flow_record.dstas 	  	  = r->dstas;
					flow_record.input 	  	  = r->input;
					flow_record.output 	  	  = r->output;

					print_record((void *)&flow_record, r->counter[FLOWS], &string, anon, tag);
					printf("%s\n", string);

					c++;
				}
			}
		}
	}

} // End of ReportAggregated

void ReportStat(char *record_header, printer_t print_record, int topN, int flow_stat, int element_stat, int anon, int tag, int pipe_output) {
SortElement_t 	*topN_flow_list[NumOrders];
SortElement_t	*topN_element_list;
master_record_t	flow_record;
uint32_t		numflows, maxindex;
int32_t 		i, j, hash_num, order_index, order_bit;
char			*string;

	flow_record.flags = 0;
	numflows = 0;
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
					print_record((void *)&flow_record, ((FlowTableRecord_t *)(topN_flow_list[order_index][i].record))->counter[FLOWS], &string, anon, tag);
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
					if ( !pipe_output ) {
						printf("Top %i %s ordered by %s:\n", topN, StatParameters[stat].HeaderInfo, order_mode[order_index].string);
						//      2005-07-26 20:08:59.197 1553.730      ss    65255   203435   52.2 M      130   281636   268
						if ( Getv6Mode() && ipconv ) 
							printf("Date first seen          Duration Proto %39s    Flows  Packets    Bytes      pps      bps   bpp\n",
								StatParameters[stat].HeaderInfo);
						else
							printf("Date first seen          Duration Proto %16s    Flows  Packets    Bytes      pps      bps   bpp\n",
								StatParameters[stat].HeaderInfo);
					}

					maxindex = ( StatTable[hash_num].NextBlock * StatTable[hash_num].Prealloc ) + StatTable[hash_num].NextElem;
					j = numflows - topN;
					j = j < 0 ? 0 : j;
					if ( topN == 0 )
						j = 0;
					for ( i=numflows-1; i>=j ; i--) {
						if ( !topN_element_list[i].count )
							break;
						if ( pipe_output ) 
							PrintPipeStatLine((StatRecord_t *)topN_element_list[i].record, ipconv, anon, StatRequest[hash_num].order_proto, tag);
						else
							PrintStatLine((StatRecord_t *)topN_element_list[i].record, ipconv, anon, StatRequest[hash_num].order_proto, tag);
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

void PrintSortedFlows(printer_t print_record, uint32_t limitflows, int anon, int tag) {
FlowTableRecord_t	*r;
SortElement_t 		*SortList;
master_record_t		flow_record;
unsigned int		i, j, tmp;
uint32_t			maxindex, c;
char				*string;

	flow_record.flags = 0;
	maxindex = ( FlowTable.NextBlock * FlowTable.Prealloc ) + FlowTable.NextElem;
	SortList = (SortElement_t *)calloc(maxindex, sizeof(SortElement_t));

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

	heapSort(SortList, maxindex, 0);

	if ( limitflows && limitflows < maxindex )
		maxindex = limitflows;
	for ( i=0; i<maxindex; i++ ) {
		r = SortList[i].record;

		flow_record.flags = r->record_flags;
		flow_record.v6.srcaddr[0] = r->ip.v6.srcaddr[0];
		flow_record.v6.srcaddr[1] = r->ip.v6.srcaddr[1];
		flow_record.v6.dstaddr[0] = r->ip.v6.dstaddr[0];
		flow_record.v6.dstaddr[1] = r->ip.v6.dstaddr[1];
		flow_record.srcport 	  = r->srcport;
		flow_record.dstport 	  = r->dstport;
		flow_record.dOctets 	  = r->counter[BYTES];
		flow_record.dPkts   	  = r->counter[PACKETS];
		flow_record.first   	  = r->first;
		flow_record.msec_first 	  = r->msec_first;
		flow_record.last 	  	  = r->last;
		flow_record.msec_last  	  = r->msec_last;
		flow_record.prot    	  = r->prot;
		flow_record.tcp_flags	  = r->tcp_flags;
		flow_record.tos    		  = r->tos;
		flow_record.srcas   	  = r->srcas;
		flow_record.dstas   	  = r->dstas;
		flow_record.input   	  = r->input;
		flow_record.output   	  = r->output;

		print_record((void *)&flow_record, 1, &string, anon, tag);

		if ( string )
			printf("%s\n", string);
	}
	
	free(SortList);

} // End of PrintSortedFlows

static SortElement_t *StatTopN(int topN, uint32_t *count, int hash_num, int order ) {
SortElement_t 		*topN_list;
StatRecord_t		*r;
unsigned int		i;
uint32_t	   		c, maxindex;

	maxindex  = ( StatTable[hash_num].NextBlock * StatTable[hash_num].Prealloc ) + StatTable[hash_num].NextElem;
	topN_list = (SortElement_t *)calloc(maxindex, sizeof(SortElement_t));

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
	
	/*
	for ( i = 0; i < maxindex; i++ ) 
		printf("%i, %llu %llu\n", i, topN_list[i].count, topN_list[i].record);
	*/

	// Sorting makes only sense, when 2 or more flows are left
	if ( c >= 2 )
 		heapSort(topN_list, c, topN);

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


	if ( val >= (topN_list)[0].count ) {
		/* element value is bigger than smallest value in topN */
		c1 = val;
		r1 = r;
		for (j=topN-1; j>=0; j-- ) {
			if ( c1 >= topN_list[j].count ) {
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
int32_t	i, maxindex;

	for(i = array_size - 1; i >= 0; i--)
		siftDown(SortElement,array_size,i);

	/* 
	 * we are only interested in the first top N => skip sorting the rest
	 * For topN == 0 -> all flows gets sorted
	 */
    if ( (topN >= (array_size - 1)) || topN == 0 )
        maxindex = 0;
    else
        maxindex = array_size - 1 - topN;

	for(i = array_size-1; i > maxindex; i-- ) {
		SortElement_t temp = SortElement[0];
		SortElement[0] = SortElement[i];
		SortElement[i] = temp;
		siftDown(SortElement,i,0);
	}

} // End of heapSort

static inline void siftDown(SortElement_t *SortElement, uint32_t numbersSize, uint32_t node) {
uint32_t i, parent, child;

    parent = node;
    i = parent + 1;
    while( i != parent ) {
        i = parent;

        // Compare with left child node
		child = 2*i+1;
        if( (child) < numbersSize && SortElement[child].count > SortElement[parent].count)
            parent = child;

        // Compare with right child node
		child = 2*i+2;
        if( (child) < numbersSize && SortElement[child].count > SortElement[parent].count)
            parent = child;

        if ( i != parent ) {
            SortElement_t temp = SortElement[i];
            SortElement[i] = SortElement[parent];
            SortElement[parent] = temp;
        }
    }
} // End of siftDown

