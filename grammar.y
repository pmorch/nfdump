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
 *  $Id: grammar.y 34 2005-08-22 12:01:31Z peter $
 *
 *  $LastChangedRevision: 34 $
 *	
 *
 *
 */

%{

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nfdump.h"
#include "nftree.h"

/*
 * function prototypes
 */
static void  yyerror(char *msg);

static uint32_t stoipaddr(char *s, uint32_t *ipaddr);

enum { SOURCE = 1, DESTINATION, SOURCE_AND_DESTINATION, SOURCE_OR_DESTINATION };

/* var defs */
extern int 			lineno;
extern char 		*yytext;
extern uint32_t	StartNode;
extern uint16_t	Extended;
extern int (*FilterEngine)(uint32_t *);

%}

%union {
	uint32_t		value;
	char			*s;
	FilterParam_t	param;
}

%token ANY IP IF NEXT TCP UDP ICMP GRE ESP AH RSVP PROTO TOS FLAGS HOST NET PORT IN OUT SRC DST EQ LT GT
%token NUMBER QUADDOT ALPHA_FLAGS PORTNUM ICMPTYPE AS PACKETS BYTES PPS BPS BPP DURATION
%token NOT END
%type <value>	expr NUMBER PORTNUM NETNUM ICMPTYPE
%type <s>	QUADDOT ALPHA_FLAGS
%type <param> dqual inout term comp scale

%left	'+' OR
%left	'*' AND
%left	NEGATE

%%
prog: 		/* empty */
	| expr 	{   
				StartNode = $1; 
			}
	;

term:	ANY					{  	/* this is an unconditionally true expression, as a filter applies in any case */
								$$.self = NewBlock(OffsetProto, 0, 0, CMP_EQ, FUNC_NONE ); }	

	| ICMP 					{  	$$.self = NewBlock(OffsetProto, MaskProto, (uint32_t)(1 << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE); }

	| TCP 					{  	$$.self = NewBlock(OffsetProto, MaskProto, (uint32_t)(6 << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE); }

	| UDP 					{  	$$.self = NewBlock(OffsetProto, MaskProto, (uint32_t)(17 << ShiftProto) & MaskProto, CMP_EQ, FUNC_NONE); }

	| RSVP 					{  	$$.self = NewBlock(OffsetProto, MaskProto, (uint32_t)(46 << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE); }

	| GRE 					{  	$$.self = NewBlock(OffsetProto, MaskProto, (uint32_t)(47 << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE); }

	| ESP 					{  	$$.self = NewBlock(OffsetProto, MaskProto, (uint32_t)(50 << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE); }

	| AH 					{  	$$.self = NewBlock(OffsetProto, MaskProto, (uint32_t)(51 << ShiftProto)  & MaskProto, CMP_EQ, FUNC_NONE); }

	| PROTO NUMBER			{	$$.self = NewBlock(OffsetProto, MaskProto, (uint32_t)($2 << ShiftProto) & MaskProto, CMP_EQ, FUNC_NONE); }
	| PACKETS comp NUMBER scale	{	
								$$.self = NewBlock(OffsetPackets, MaskSize, (uint32_t)$3 * $4.scale, $2.comp, FUNC_NONE); 
							}

	| BYTES comp NUMBER scale {	
								$$.self = NewBlock(OffsetBytes, MaskSize, (uint32_t)$3 * $4.scale , $2.comp, FUNC_NONE); 
							}

	| PPS comp NUMBER scale	{	
								$$.self = NewBlock(0, AnyMask, (uint32_t)$3 * $4.scale , $2.comp, FUNC_PPS); 
							}

	| BPS comp NUMBER scale	{	
								$$.self = NewBlock(0, AnyMask, (uint32_t)$3 * $4.scale , $2.comp, FUNC_BPS); 
							}

	| BPP comp NUMBER scale	{	
								$$.self = NewBlock(0, AnyMask, (uint32_t)$3 * $4.scale , $2.comp, FUNC_BPP); 
							}

	| DURATION comp NUMBER  {	
								$$.self = NewBlock(0, AnyMask, (uint32_t)$3, $2.comp, FUNC_DURATION); 
							}

	| TOS comp NUMBER			{	
								if ( $3 > 255 ) {
									yyerror("TOS must be 0..255");
									YYABORT;
								}
								$$.self = NewBlock(OffsetTos, MaskTos, (uint32_t)($3 << ShiftTos) & MaskTos, $2.comp, FUNC_NONE); 

							}

	| FLAGS comp NUMBER		{	if ( $3 > 63 ) {
									yyerror("Flags must be 0..63");
									YYABORT;
								}
								$$.self = NewBlock(OffsetFlags, MaskFlags, (uint32_t)($3 << ShiftFlags) & MaskFlags, $2.comp, FUNC_NONE); 
							}

	| FLAGS ALPHA_FLAGS		{	
								int fl = 0;
								if ( strlen($2) > 7 ) {
									yyerror("Too many flags");
									YYABORT;
								}

								if ( strchr($2, 'F') ) fl |=  1;
								if ( strchr($2, 'S') ) fl |=  2;
								if ( strchr($2, 'R') ) fl |=  4;
								if ( strchr($2, 'P') ) fl |=  8;
								if ( strchr($2, 'A') ) fl |=  16;
								if ( strchr($2, 'U') ) fl |=  32;
								if ( strchr($2, 'X') ) fl =  63;

								$$.self = NewBlock(OffsetFlags, (uint32_t)(fl << ShiftFlags) & MaskFlags, (uint32_t)(fl << ShiftFlags) & MaskFlags, CMP_EQ, FUNC_NONE); 
							}

	| dqual HOST QUADDOT		{ 	if ( !stoipaddr($3, &$$.ip) ) 
									YYABORT;
								$$.direction = $1.direction;
								if ( $$.direction == SOURCE ) {
									$$.self = NewBlock(OffsetSrcIP, MaskIP, $$.ip, CMP_EQ, FUNC_NONE );
								} else if ( $$.direction == DESTINATION) {
									$$.self = NewBlock(OffsetDstIP, MaskIP, $$.ip, CMP_EQ, FUNC_NONE );
								} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
									$$.self = Connect_OR(
										NewBlock(OffsetSrcIP, MaskIP, $$.ip, CMP_EQ, FUNC_NONE ),
										NewBlock(OffsetDstIP, MaskIP, $$.ip, CMP_EQ, FUNC_NONE )
									);
								} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
									$$.self = Connect_AND(
										NewBlock(OffsetSrcIP, MaskIP, $$.ip, CMP_EQ, FUNC_NONE ),
										NewBlock(OffsetDstIP, MaskIP, $$.ip, CMP_EQ, FUNC_NONE )
									);
								} else {
									/* should never happen */
									yyerror("Internal parser error");
									YYABORT;
								}
							}

	| dqual IP QUADDOT		{	if ( !stoipaddr($3, &$$.ip) ) 
									YYABORT;

								$$.direction = $1.direction;
								if ( $$.direction == SOURCE ) {
									$$.self = NewBlock(OffsetSrcIP, MaskIP, $$.ip, CMP_EQ, FUNC_NONE );
								} else if ( $$.direction == DESTINATION) {
									$$.self = NewBlock(OffsetDstIP, MaskIP, $$.ip, CMP_EQ, FUNC_NONE );
								} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
									$$.self = Connect_OR(
										NewBlock(OffsetSrcIP, MaskIP, $$.ip, CMP_EQ, FUNC_NONE ),
										NewBlock(OffsetDstIP, MaskIP, $$.ip, CMP_EQ, FUNC_NONE )
									);
								} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
									$$.self = Connect_AND(
										NewBlock(OffsetSrcIP, MaskIP, $$.ip, CMP_EQ, FUNC_NONE ),
										NewBlock(OffsetDstIP, MaskIP, $$.ip, CMP_EQ, FUNC_NONE )
									);
								} else {
									/* should never happen */
									yyerror("Internal parser error");
									YYABORT;
								}

							}

	| NEXT QUADDOT			{	if ( !stoipaddr($2, &$$.ip) ) 
									YYABORT;

								$$.self = NewBlock(OffsetNext, MaskIP, $$.ip, CMP_EQ, FUNC_NONE );

							}

	| dqual PORT comp NUMBER	{	$$.direction = $1.direction;
								if ( $4 > 65535 ) {
									yyerror("Port outside of range 0..65535");
									YYABORT;
								}

								if ( $$.direction == SOURCE ) {
									$$.self = NewBlock(OffsetPort, MaskSrcPort, ($4 << ShiftSrcPort) & MaskSrcPort, $3.comp, FUNC_NONE );
								} else if ( $$.direction == DESTINATION) {
									$$.self = NewBlock(OffsetPort, MaskDstPort, ($4 << ShiftDstPort) & MaskDstPort, $3.comp, FUNC_NONE );
								} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
									$$.self = Connect_OR(
										NewBlock(OffsetPort, MaskSrcPort, ($4 << ShiftSrcPort) & MaskSrcPort, $3.comp, FUNC_NONE ),
										NewBlock(OffsetPort, MaskDstPort, ($4 << ShiftDstPort) & MaskDstPort, $3.comp, FUNC_NONE )
									);
								} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
									$$.self = Connect_AND(
										NewBlock(OffsetPort, MaskSrcPort, ($4 << ShiftSrcPort) & MaskSrcPort, $3.comp, FUNC_NONE ),
										NewBlock(OffsetPort, MaskDstPort, ($4 << ShiftDstPort) & MaskDstPort, $3.comp, FUNC_NONE )
									);
								} else {
									/* should never happen */
									yyerror("Internal parser error");
									YYABORT;
								}
							}

| dqual AS NUMBER		{	$$.direction = $1.direction;
								if ( $3 > 65535 || $3 < 1 ) {
									yyerror("AS number outside of range 1..65535");
									YYABORT;
								}

								if ( $$.direction == SOURCE ) {
									$$.self = NewBlock(OffsetAS, MaskSrcAS, ($3 << ShiftSrcAS) & MaskSrcAS, CMP_EQ, FUNC_NONE );
								} else if ( $$.direction == DESTINATION) {
									$$.self = NewBlock(OffsetAS, MaskDstAS, ($3 << ShiftDstAS) & MaskDstAS, CMP_EQ, FUNC_NONE);
								} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
									$$.self = Connect_OR(
										NewBlock(OffsetAS, MaskSrcAS, ($3 << ShiftSrcAS) & MaskSrcAS, CMP_EQ, FUNC_NONE ),
										NewBlock(OffsetAS, MaskDstAS, ($3 << ShiftDstAS) & MaskDstAS, CMP_EQ, FUNC_NONE)
									);
								} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
									$$.self = Connect_AND(
										NewBlock(OffsetPort, MaskSrcAS, ($3 << ShiftSrcAS) & MaskSrcAS, CMP_EQ, FUNC_NONE ),
										NewBlock(OffsetPort, MaskDstAS, ($3 << ShiftDstAS) & MaskDstAS, CMP_EQ, FUNC_NONE)
									);
								} else {
									/* should never happen */
									yyerror("Internal parser error");
									YYABORT;
								}
							}

	| dqual NET QUADDOT NETNUM	{ 	if ( !stoipaddr($3, &$$.ip) ) 
									YYABORT;
								$$.direction = $1.direction;
								if ( $$.direction == SOURCE ) {
									$$.self = NewBlock(OffsetSrcIP, $4, $$.ip & $4, CMP_EQ, FUNC_NONE);
								} else if ( $$.direction == DESTINATION) {
									$$.self = NewBlock(OffsetDstIP, $4, $$.ip & $4, CMP_EQ, FUNC_NONE);
								} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
									$$.self = Connect_OR(
										NewBlock(OffsetSrcIP, $4, $$.ip & $4, CMP_EQ, FUNC_NONE),
										NewBlock(OffsetDstIP, $4, $$.ip & $4, CMP_EQ, FUNC_NONE)
									);
								} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
									$$.self = Connect_AND(
										NewBlock(OffsetSrcIP, $4, $$.ip & $4, CMP_EQ, FUNC_NONE),
										NewBlock(OffsetDstIP, $4, $$.ip & $4, CMP_EQ, FUNC_NONE)
									);
								} else {
									/* should never happen */
									yyerror("Internal parser error");
									YYABORT;
								}

							}

	| inout IF NUMBER		{
								if ( $3 > 65535 ) {
									yyerror("Input interface number must be 0..65535");
									YYABORT;
								}
								if ( $$.direction == SOURCE ) {
									$$.self = NewBlock(OffsetInOut, MaskInput, (uint32_t)($3 << ShiftInput) & MaskInput, CMP_EQ, FUNC_NONE); 
								} else if ( $$.direction == DESTINATION) {
									$$.self = NewBlock(OffsetInOut, MaskOutput, (uint32_t)($3 << ShiftOutput) & MaskOutput, CMP_EQ, FUNC_NONE); 
								} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
									$$.self = Connect_OR(
										NewBlock(OffsetInOut, MaskInput, (uint32_t)($3 << ShiftInput) & MaskInput, CMP_EQ, FUNC_NONE),
										NewBlock(OffsetInOut, MaskOutput, (uint32_t)($3 << ShiftOutput) & MaskOutput, CMP_EQ, FUNC_NONE)
									);
								} else {
									/* should never happen */
									yyerror("Internal parser error");
									YYABORT;
								}
							}

	| ICMP ICMPTYPE			{ 	$$.proto = 1; 

							}
	;

NETNUM:	QUADDOT				{ if ( !stoipaddr($1, &$$) )
                                    YYABORT;
	  						}
	| '/' NUMBER			{ if ( $2 > 32 || $2 < 1 ) {
									yyerror("Mask bits outside of range 1..32");
									YYABORT;
							  }
							  $$ = 0xffffffff << ( 32 - $2 );
							  /* $$ = !( 1 << ( $2 -1 ) ); */

							}
	;

/* scaling  qualifiers */
scale:				{ $$.scale = 1; }
	| 'k'			{ $$.scale = 1024; }
	| 'm'			{ $$.scale = 1024*1024; }
	| 'g'			{ $$.scale = 1024*1024*1024; }
	;

/* comparator qualifiers */
comp:				{ $$.comp = CMP_EQ; }
	| EQ			{ $$.comp = CMP_EQ; }
	| LT			{ $$.comp = CMP_LT; }
	| GT			{ $$.comp = CMP_GT; }
	;

/* 'direction' qualifiers */
dqual:	  			{ $$.direction = SOURCE_OR_DESTINATION;  }
	| SRC			{ $$.direction = SOURCE;				 }
	| DST			{ $$.direction = DESTINATION;			 }
	| SRC OR DST 	{ $$.direction = SOURCE_OR_DESTINATION;  }
	| DST OR SRC	{ $$.direction = SOURCE_OR_DESTINATION;  }
	| SRC AND DST	{ $$.direction = SOURCE_AND_DESTINATION; }
	| DST AND SRC	{ $$.direction = SOURCE_AND_DESTINATION; }
	;

inout:	  			{ $$.direction = SOURCE_OR_DESTINATION;  }
	| IN			{ $$.direction = SOURCE;				 }
	| OUT			{ $$.direction = DESTINATION;			 }
	;

expr:	term		{ $$ = $1.self;        }
	| expr OR  expr	{ $$ = Connect_OR($1, $3);  }
	| expr AND expr	{ $$ = Connect_AND($1, $3); }
	| NOT expr	%prec NEGATE	{ $$ = Invert($2);			}
	| '(' expr ')'	{ $$ = $2; }
	;

%%

static void  yyerror(char *msg) {
	fprintf(stderr,"line %d: %s at '%s'\n", lineno, msg, yytext);
} /* End of yyerror */

uint32_t stoipaddr(char *s, uint32_t *ipaddr) {
	uint	n, i;
	char *p, *q;
	
	*ipaddr = 0;
	p = s;
	for ( i=0; i < 4; i++ ) {
		if ( p ) {
			if ((q = strchr(p,'.')) != NULL ) {
				*q = 0;
			}
			n = atoi(p);
			if ( n < 0 || n > 255 ) {
				yyerror("Bad IP address");
				return 0;
			}
			if ( q ) 
				p = q + 1;
			else 
				p = NULL;
		} else {
			n = 0;
		}
		*ipaddr = ( *ipaddr << 8 ) | n;
	}
	return 1;

} /* End of stoipaddr */


