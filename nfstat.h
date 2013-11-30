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
 *  $Id: nfstat.h 88 2007-03-06 08:49:26Z peter $
 *
 *  $LastChangedRevision: 88 $
 *	
 */

/* Definitions */

/* 
 * Common type for FlowTableRecord_t and StatRecord_t
 * Needed for some common functions 
 * No variable is ever generated of this type. It's just needed for type coercing
 * Maybe some day I will rewrite that ... to make it easier
 */
typedef struct CommonRecord_s {
	// record chain - points to next record
	struct CommonRecord_s *next;	
	// flow counter parameters for FLOWS, PACKETS and BYTES
	uint64_t	counter[3];
	uint32_t	first;
	uint32_t	last;
	uint16_t	msec_first;
	uint16_t	msec_last;
} CommonRecord_t;

/*
 * Flow Table
 * In order to aggregate flows or to generate any flow statistics, the flows passed the filter
 * are stored into an internal hash table.
 */

/* Element of the Flow Table */
typedef struct FlowTableRecord {
	// record chain - points to next record with same hash in case of a hash collision
	struct FlowTableRecord *next;	
	// flow counter parameters for FLOWS, PACKETS and BYTES
	uint64_t	counter[3];
	uint32_t	first;
	uint32_t	last;
	uint16_t	msec_first;
	uint16_t	msec_last;

	// more flow parameters
  	uint8_t   	record_flags;
  	uint8_t   	tcp_flags;
  	uint8_t   	prot;
  	uint8_t   	tos;

	uint16_t	input;
	uint16_t	output;
	uint16_t	srcas;
	uint16_t	dstas;

	// elements used for hash generation
	uint16_t	srcport;
	uint16_t	dstport;
	ip_block_t	ip;
} FlowTableRecord_t;

typedef struct hash_FlowTable {
	/* hash table data */
	uint16_t 			NumBits;		/* width of the hash table */
	uint32_t			IndexMask;		/* Mask which corresponds to NumBits */
	FlowTableRecord_t 	**bucket;		/* Hash entry point: points to elements in the flow block */
	FlowTableRecord_t 	**bucketcache;	/* in case of index collisions, this array points to the last element with that index */

	/* memory management */
	/* memory blocks - containing the flow blocks */
	FlowTableRecord_t	**memblock;		/* array holding all NumBlocks allocated flow blocks */
	uint32_t 			MaxBlocks;		/* Size of memblock array */
	/* flow blocks - containing the flows */
	uint32_t 			NumBlocks;		/* number of allocated flow blocks in memblock array */
	uint32_t 			Prealloc;		/* Number of flow records in each flow block */
	uint32_t			NextBlock;		/* This flow block contains the next free slot for a flow recorrd */
	uint32_t			NextElem;		/* This element in the current flow block is the next free slot */
} hash_FlowTable;

/*
 * Stat Table
 * In order to generate any flow element statistics, the flows passed the filter
 * are stored into an internal hash table.
 */

typedef struct StatRecord {
	// record chain
	struct StatRecord *next;
	// flow parameters
	uint64_t	counter[3];
	uint32_t	first;
	uint32_t	last;
	uint16_t	msec_first;
	uint16_t	msec_last;
	uint8_t		record_flags;
	uint8_t		tcp_flags;
	uint8_t		tos;
	// key 
	uint8_t		prot;
	uint64_t	stat_key[2];
} StatRecord_t;

typedef struct hash_StatTable {
	/* hash table data */
	uint16_t 			NumBits;		/* width of the hash table */
	uint32_t			IndexMask;		/* Mask which corresponds to NumBits */
	StatRecord_t 		**bucket;		/* Hash entry point: points to elements in the stat block */
	StatRecord_t 		**bucketcache;	/* in case of index collisions, this array points to the last element with that index */

	/* memory management */
	/* memory blocks - containing the stat records */
	StatRecord_t		**memblock;		/* array holding all NumBlocks allocated stat blocks */
	uint32_t 			MaxBlocks;		/* Size of memblock array */
	/* stat blocks - containing the stat records */
	uint32_t 			NumBlocks;		/* number of allocated stat blocks in memblock array */
	uint32_t 			Prealloc;		/* Number of stat records in each stat block */
	uint32_t			NextBlock;		/* This stat block contains the next free slot for a stat recorrd */
	uint32_t			NextElem;		/* This element in the current stat block is the next free slot */
} hash_StatTable;

typedef struct SortElement {
	void 		*record;
    uint64_t	count;
} SortElement_t;

#define Aggregate_SRCIP		1
#define Aggregate_DSTIP		2
#define Aggregate_SRCPORT	4
#define Aggregate_DSTPORT	8
#define Aggregate_SRCAS		16
#define Aggregate_DSTAS		32
#define Aggregate_PROTO		64

/* Function prototypes */
void SetLimits(int stat, char *packet_limit_string, char *byte_limit_string );

int Init_FlowTable(uint16_t NumBits, uint32_t Prealloc);

int Init_StatTable(uint16_t NumBits, uint32_t Prealloc);

void Dispose_Tables(int flow_stat, int ip_stat);

char *VerifyStat(uint16_t Aggregate_Bits);

int SetStat(char *str, int *element_stat, int *flow_stat);

int SetStat_DefaultOrder(char *order);

void InsertFlow(master_record_t *flow_record);

int AddStat(data_block_header_t *flow_header, master_record_t *flow_record, int flow_stat, int element_stat,
			int aggregate, uint64_t *AggregateMasks );

void ReportAggregated(printer_t print_record, uint32_t limitflows, int date_sorted, int anon, int tag);

void ReportStat(char *record_header, printer_t print_record, int topN, int flow_stat, int ip_stat, int anon, int tag, int pipe_output);

void PrintSortedFlows(printer_t print_record, uint32_t limitflows, int anon, int tag);
