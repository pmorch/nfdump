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
 *  $Id: nfstat.h 2 2004-09-20 18:12:36Z peter $
 *
 *  $LastChangedRevision: 2 $
 *	
 */

/* Definitions */

typedef struct FlowTableRecord {
	// record chain
	struct FlowTableRecord *next;
	// key validation parameters
	uint32_t	ip1;
	uint32_t	ip2;
	uint16_t	port1;
	uint16_t	port2;
	// flow parameters
	uint64_t	bytes;
	uint64_t	pkts;
	time_t		first;
	time_t		last;
	uint32_t	proto;
	uint64_t	numflows;
} FlowTableRecord_t;

typedef struct IPDataRecord {
	// record chain
	struct IPDataRecord *next;
	// key validation parameters
	uint32_t	ip1;
	// flow parameters
	uint64_t	bytes;
	uint64_t	pkts;
	time_t		first;
	time_t		last;
	uint32_t	proto;
	uint64_t	numflows;
} IPDataRecord_t;

typedef struct hash_FlowTable {
	uint16_t 			NumBits;
	uint16_t 			NumBlocks;
	uint16_t 			MaxBlocks;
	uint32_t			IndexMask;
	uint32_t 			Prealloc;
	FlowTableRecord_t	**memblocks;
	FlowTableRecord_t 	**bucket;
	FlowTableRecord_t 	**bucketcache;
	uint32_t			NextBlock;
	uint32_t			NextElem;
} hash_FlowTable;

typedef struct hash_IPTable {
	uint16_t 			NumBits;
	uint16_t 			NumBlocks;
	uint16_t 			MaxBlocks;
	uint32_t			IndexMask;
	uint32_t 			Prealloc;
	IPDataRecord_t		**memblocks;
	IPDataRecord_t 		**bucket;
	IPDataRecord_t 		**bucketcache;
	uint32_t			NextBlock;
	uint32_t			NextElem;
} hash_IPTable;

typedef struct SortElement {
	void 		*record;
    uint64_t	count;
} SortElement_t;


/* Function prototypes */
int Init_FlowTable(uint16_t NumBits, uint32_t Prealloc);

int Init_IPTable(uint16_t NumBits, uint32_t Prealloc);

void Dispose_Tables(int flow_stat, int ip_stat);

int AddStat(nf_header_t *nf_header, nf_record_t *nf_record, 
				int flow_stat, int src_ip_stat, int dst_ip_stat);

void ReportAggregated(uint32_t limitflows, int date_sorted);

void ReportStat(int topN, int flow_stat, int ip_stat);

void PrintSortedFlows(void);

void list_insert(nf_record_t *nf_record);
