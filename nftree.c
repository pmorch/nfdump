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
 *  $Id: nftree.c 2 2004-09-20 18:12:36Z peter $
 *
 *  $LastChangedRevision: 2 $
 *	
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nfdump.h"
#include "nftree.h"
#include "grammar.h"
/*
 * netflow filter engine
 *
 */

#define MAXBLOCKS 1024

static FilterBlock_t *FilterTree;
static uint32_t memblocks;

static uint32_t NumBlocks = 1;	/* index 0 reserved */

static void UpdateList(uint32_t a, uint32_t b);

uint32_t StartNode;
uint16_t Extended;

void InitTree(void) {
	memblocks = 1;
	FilterTree = (FilterBlock_t *)malloc(MAXBLOCKS * sizeof(FilterBlock_t));
	if ( !FilterTree ) {
		perror("Memory error: ");
		exit(255);
	}
	ClearFilter();
} // End of InitTree

/*
 * Clear Filter
 */
void ClearFilter(void) {

	NumBlocks = 1;
	Extended  = 0;
	memset((void *)FilterTree, 0, MAXBLOCKS * sizeof(FilterBlock_t));

} /* End of ClearFilter */

FilterEngine_data_t *CompileFilter(char *FilterSyntax) {
FilterEngine_data_t	*engine;
int	ret;

	if ( !FilterSyntax ) 
		return NULL;

	InitTree();
	lex_init(FilterSyntax);
	ret = yyparse();
	lex_cleanup();
	if ( ret != 0 ) {
		return NULL;
	}
	engine = malloc(sizeof(FilterEngine_data_t));
	if ( !engine ) {
		perror("Memory error: ");
		exit(255);
	}
	engine->nfrecord  = NULL;
	engine->StartNode = StartNode;
	engine->Extended  = Extended;
	engine->filter 	  = FilterTree;
	if ( Extended ) 
		engine->FilterEngine = RunExtendedFilter;
	else
		engine->FilterEngine = RunFilter;

	return engine;

} // End of GetTree

/*
 * For testing purpose only
 */
int nblocks(void) {
	return NumBlocks - 1;
} /* End of nblocks */

/* 
 * Returns next free slot in blocklist
 */
uint32_t	NewBlock(uint32_t offset, uint32_t mask, uint32_t value, uint16_t comp) {
	uint32_t	n = NumBlocks;

	if ( n >= ( memblocks * MAXBLOCKS ) ) {
		memblocks++;
		FilterTree = realloc(FilterTree, memblocks * MAXBLOCKS * sizeof(FilterBlock_t));
		if ( !FilterTree ) {
			perror("Memory error: ");
			exit(255);
		}
	}

	FilterTree[n].offset	= offset;
	FilterTree[n].mask		= mask;
	FilterTree[n].value		= value;
	FilterTree[n].invert	= 0;
	FilterTree[n].comp 		= comp;
	if ( comp > 0 )
		Extended = 1;

	FilterTree[n].numblocks = 1;
	FilterTree[n].blocklist = (uint32_t *)malloc(sizeof(uint32_t));
	FilterTree[n].superblock = n;
	FilterTree[n].blocklist[0] = n;
	NumBlocks++;
	return n;

} /* End of NewBlock */

/* 
 * Connects the two blocks b1 and b2 ( AND ) and returns index of superblock
 */
uint32_t	Connect_AND(uint32_t b1, uint32_t b2) {

	uint32_t	a, b, i, j;

	if ( FilterTree[b1].numblocks <= FilterTree[b2].numblocks ) {
		a = b1;
		b = b2;
	} else {
		a = b2;
		b = b1;
	}
	/* a points to block with less children and becomes the superblock 
	 * connect b to a
	 */
	for ( i=0; i < FilterTree[a].numblocks; i++ ) {
		j = FilterTree[a].blocklist[i];
		if ( FilterTree[j].invert ) {
			if ( FilterTree[j].OnFalse == 0 ) {
				FilterTree[j].OnFalse = b;
			}
		} else {
			if ( FilterTree[j].OnTrue == 0 ) {
				FilterTree[j].OnTrue = b;
			}
		}
	}
	UpdateList(a,b);
	return a;

} /* End of Connect_AND */

/* 
 * Connects the two blocks b1 and b2 ( OR ) and returns index of superblock
 */
uint32_t	Connect_OR(uint32_t b1, uint32_t b2) {

	uint32_t	a, b, i, j;

	if ( FilterTree[b1].numblocks <= FilterTree[b2].numblocks ) {
		a = b1;
		b = b2;
	} else {
		a = b2;
		b = b1;
	}
	/* a points to block with less children and becomes the superblock 
	 * connect b to a
	 */
	for ( i=0; i < FilterTree[a].numblocks; i++ ) {
		j = FilterTree[a].blocklist[i];
		if ( FilterTree[j].invert ) {
			if ( FilterTree[j].OnTrue == 0 ) {
				FilterTree[j].OnTrue = b;
			}
		} else {
			if ( FilterTree[j].OnFalse == 0 ) {
				FilterTree[j].OnFalse = b;
			}
		}
	}
	UpdateList(a,b);
	return a;

} /* End of Connect_OR */

/* 
 * Inverts OnTrue and OnFalse
 */
uint32_t	Invert(uint32_t a) {
	uint32_t	i, j;

	for ( i=0; i< FilterTree[a].numblocks; i++ ) {
		j = FilterTree[a].blocklist[i];
		FilterTree[j].invert = FilterTree[j].invert ? 0 : 1 ;
	}
	return a;

} /* End of Invert */

/*
 * Update supernode infos:
 * node 'b' was connected to 'a'. update node 'a' supernode data
 */
static void UpdateList(uint32_t a, uint32_t b) {
	size_t s;
	uint32_t	i,j;

	/* numblocks contains the number of blocks in the superblock */
	s = FilterTree[a].numblocks + FilterTree[b].numblocks;
	FilterTree[a].blocklist = (uint32_t *)realloc(FilterTree[a].blocklist, s * sizeof(uint32_t));
	if ( !FilterTree[a].blocklist ) {
		perror("Memory error: ");
		exit(250);
	}

	/* connect list of node 'b' after list of node 'a' */
	j = FilterTree[a].numblocks;
	for ( i=0; i< FilterTree[b].numblocks; i++ ) {
		FilterTree[a].blocklist[j+i] = FilterTree[b].blocklist[i];
	}
	FilterTree[a].numblocks = s;

	/* set superblock info of all children to new superblock */
	for ( i=0; i< FilterTree[a].numblocks; i++ ) {
		j = FilterTree[a].blocklist[i];
		FilterTree[j].superblock = a;
	}

	/* cleanup old node 'b' */
	FilterTree[b].numblocks = 0;
	if ( FilterTree[b].blocklist ) 
		free(FilterTree[b].blocklist);

} /* End of UpdateList */

/*
 * Dump Filterlist 
 */
void DumpList(FilterEngine_data_t *args) {
	uint32_t i, j;

	for (i=1; i<NumBlocks; i++ ) {
		if ( args->filter[i].invert )
			printf("Index: %u, Offset: %u, Mask: %x, Value: %x, Superblock: %u, Numblocks: %u, !OnTrue: %u, !OnFalse: %u Comp: %u\n",
				i, args->filter[i].offset, args->filter[i].mask, args->filter[i].value, args->filter[i].superblock, 
				args->filter[i].numblocks, args->filter[i].OnTrue, args->filter[i].OnFalse, args->filter[i].comp);
		else 
			printf("Index: %u, Offset: %u, Mask: %x, Value: %x, Superblock: %u, Numblocks: %u, OnTrue: %u, OnFalse: %u Comp: %u\n",
				i, args->filter[i].offset, args->filter[i].mask, args->filter[i].value, args->filter[i].superblock, 
				args->filter[i].numblocks, args->filter[i].OnTrue, args->filter[i].OnFalse, args->filter[i].comp);
		printf("\tBlocks: ");
		for ( j=0; j<args->filter[i].numblocks; j++ ) 
			printf("%i ", args->filter[i].blocklist[j]);
		printf("\n");
	}
	printf("NumBlocks: %i\n", NumBlocks - 1);

} /* End of DumpList */

int RunFilter(FilterEngine_data_t *args) {
uint32_t	index, offset;
int	evaluate, invert;

	index = args->StartNode;
	evaluate = 0;
	invert = 0;
	while ( index ) {
		offset   = args->filter[index].offset;
		invert   = args->filter[index].invert;
		evaluate = ( args->nfrecord[offset] & args->filter[index].mask ) == args->filter[index].value;
		index    = evaluate ?  args->filter[index].OnTrue : args->filter[index].OnFalse;
	}
	return invert ? !evaluate : evaluate;

} /* End of RunFilter */

int RunExtendedFilter(FilterEngine_data_t *args) {
uint32_t	index, offset;
int	evaluate, invert;

	index = args->StartNode;
	evaluate = 0;
	invert = 0;
	while ( index ) {
		offset   = args->filter[index].offset;
		invert   = args->filter[index].invert;

		if ( args->filter[index].comp == 0 )
			evaluate = ( args->nfrecord[offset] & args->filter[index].mask ) == args->filter[index].value;
		else if ( args->filter[index].comp == 1 ) 
			evaluate = ( args->nfrecord[offset] & args->filter[index].mask ) > args->filter[index].value;
		else if ( args->filter[index].comp == 2 ) 
			evaluate = ( args->nfrecord[offset] & args->filter[index].mask ) < args->filter[index].value;

		index    = evaluate ?  args->filter[index].OnTrue : args->filter[index].OnFalse;
	}
	return invert ? !evaluate : evaluate;

} /* End of RunExtendedFilter */

