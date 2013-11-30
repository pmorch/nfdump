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
 *  $Id: nftree.h 2 2004-09-20 18:12:36Z peter $
 *
 *  $LastChangedRevision: 2 $
 *	
 */


/*
 * type definitions for nf tree
 */

typedef struct FilterBlock {
	/* Filter specific data */
	uint32_t	offset;
	uint32_t	mask;
	uint32_t	value;

	/* Internal block info for tree setup */
	uint32_t	superblock;			/* Index of superblock */
	uint32_t	*blocklist;			/* index array of blocks, belonging to
								   	   this superblock */
	uint32_t	numblocks;			/* number of blocks in blocklist */
	uint32_t	OnTrue, OnFalse;	/* Jump Index for tree */
	int			invert;				/* Invert result of test */
	uint16_t	comp;				/* comperator */
} FilterBlock_t;

typedef struct FilterEngine_data_s {
	FilterBlock_t	*filter;
	uint32_t		StartNode;
	uint16_t 		Extended;
	uint32_t		*nfrecord;
	int (*FilterEngine)(struct FilterEngine_data_s *);
} FilterEngine_data_t;

/* 
 * Filter Engine Functions
 */
int RunFilter(FilterEngine_data_t *args);
int RunExtendedFilter(FilterEngine_data_t *args);
/*
 * For testing purpose only
 */
int nblocks(void);

/*
 * Initialize globals
 */
void InitTree(void);

/*
 * Returns the current Filter Tree
 */
FilterEngine_data_t *CompileFilter(char *FilterSyntax);

/*
 * Clear Filter
 */
void ClearFilter(void);

/* 
 * Returns next free slot in blocklist
 */
uint32_t	NewBlock(uint32_t offset, uint32_t mask, uint32_t value, uint16_t comp);

/* 
 * Connects the to blocks b1 and b2 ( AND ) and returns index of superblock
 */
uint32_t	Connect_AND(uint32_t b1, uint32_t b2);

/* 
 * Connects the to blocks b1 and b2 ( OR ) and returns index of superblock
 */
uint32_t	Connect_OR(uint32_t b1, uint32_t b2);

/* 
 * Inverts OnTrue and OnFalse
 */
uint32_t	Invert(uint32_t a );

/*
 * Dump Filterlist 
 */
void DumpList(FilterEngine_data_t *args);

/* 
 * Prints info while filer is running
 */
int RunDebugFilter(uint32_t	*block);
