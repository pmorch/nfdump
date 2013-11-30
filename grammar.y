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
 *  $Id: grammar.y 2 2004-09-20 18:12:36Z peter $
 *
 *  $LastChangedRevision: 2 $
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

enum { CMP_EQ = 0, CMP_GT, CMP_LT };

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

%token ANY IP TCP UDP ICMP PROTO HOST NET PORT SRC DST EQ LT GT
%token NUMBER QUADDOT PORTNUM ICMPTYPE AS
%token NOT END
%type <value>	expr NUMBER PORTNUM NETNUM ICMPTYPE
%type <s>	QUADDOT
%type <param> dqual term comp

%left	'+' OR
%left	'*' AND
%left	NEGATE

%%
prog: 		/* empty */
	| expr 	{   
				StartNode = $1; 
			}
	;

term:	ANY					{  	/* this is an unconditionally true expression, because netflow data is only IP */
								$$.self = NewBlock(OffsetProto, 0, 0, CMP_EQ ); }	

	| TCP 					{  	$$.self = NewBlock(OffsetProto, MaskProto, (uint32_t)(6 << ShiftProto)  & MaskProto, CMP_EQ); }

	| UDP 					{  	$$.self = NewBlock(OffsetProto, MaskProto, (uint32_t)(17 << ShiftProto) & MaskProto, CMP_EQ); }

	| ICMP 					{  	$$.self = NewBlock(OffsetProto, MaskProto, (uint32_t)(1 << ShiftProto)  & MaskProto, CMP_EQ); }

	| PROTO NUMBER			{	$$.self = NewBlock(OffsetProto, MaskProto, (uint32_t)($2 << ShiftProto) & MaskProto, CMP_EQ); }

	| dqual HOST QUADDOT		{ 	if ( !stoipaddr($3, &$$.ip) ) 
									YYABORT;
								$$.direction = $1.direction;
								if ( $$.direction == SOURCE ) {
									$$.self = NewBlock(OffsetSrcIP, MaskIP, $$.ip, CMP_EQ );
								} else if ( $$.direction == DESTINATION) {
									$$.self = NewBlock(OffsetDstIP, MaskIP, $$.ip, CMP_EQ );
								} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
									$$.self = Connect_OR(
										NewBlock(OffsetSrcIP, MaskIP, $$.ip, CMP_EQ ),
										NewBlock(OffsetDstIP, MaskIP, $$.ip, CMP_EQ )
									);
								} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
									$$.self = Connect_AND(
										NewBlock(OffsetSrcIP, MaskIP, $$.ip, CMP_EQ ),
										NewBlock(OffsetDstIP, MaskIP, $$.ip, CMP_EQ )
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
									$$.self = NewBlock(OffsetSrcIP, MaskIP, $$.ip, CMP_EQ );
								} else if ( $$.direction == DESTINATION) {
									$$.self = NewBlock(OffsetDstIP, MaskIP, $$.ip, CMP_EQ );
								} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
									$$.self = Connect_OR(
										NewBlock(OffsetSrcIP, MaskIP, $$.ip, CMP_EQ ),
										NewBlock(OffsetDstIP, MaskIP, $$.ip, CMP_EQ )
									);
								} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
									$$.self = Connect_AND(
										NewBlock(OffsetSrcIP, MaskIP, $$.ip, CMP_EQ ),
										NewBlock(OffsetDstIP, MaskIP, $$.ip, CMP_EQ )
									);
								} else {
									/* should never happen */
									yyerror("Internal parser error");
									YYABORT;
								}

							}

	| dqual PORT comp NUMBER	{	$$.direction = $1.direction;
								if ( $4 > 65535 ) {
									yyerror("Port outside of range 0..65535");
									YYABORT;
								}

								if ( $$.direction == SOURCE ) {
									$$.self = NewBlock(OffsetPort, MaskSrcPort, ($4 << ShiftSrcPort) & MaskSrcPort, $3.comp );
								} else if ( $$.direction == DESTINATION) {
									$$.self = NewBlock(OffsetPort, MaskDstPort, ($4 << ShiftDstPort) & MaskDstPort, $3.comp );
								} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
									$$.self = Connect_OR(
										NewBlock(OffsetPort, MaskSrcPort, ($4 << ShiftSrcPort) & MaskSrcPort, $3.comp ),
										NewBlock(OffsetPort, MaskDstPort, ($4 << ShiftDstPort) & MaskDstPort, $3.comp )
									);
								} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
									$$.self = Connect_AND(
										NewBlock(OffsetPort, MaskSrcPort, ($4 << ShiftSrcPort) & MaskSrcPort, $3.comp ),
										NewBlock(OffsetPort, MaskDstPort, ($4 << ShiftDstPort) & MaskDstPort, $3.comp )
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
									$$.self = NewBlock(OffsetAS, MaskSrcAS, ($3 << ShiftSrcAS) & MaskSrcAS, CMP_EQ );
								} else if ( $$.direction == DESTINATION) {
									$$.self = NewBlock(OffsetAS, MaskDstAS, ($3 << ShiftDstAS) & MaskDstAS, CMP_EQ);
								} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
									$$.self = Connect_OR(
										NewBlock(OffsetAS, MaskSrcAS, ($3 << ShiftSrcAS) & MaskSrcAS, CMP_EQ ),
										NewBlock(OffsetAS, MaskDstAS, ($3 << ShiftDstAS) & MaskDstAS, CMP_EQ)
									);
								} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
									$$.self = Connect_AND(
										NewBlock(OffsetPort, MaskSrcAS, ($3 << ShiftSrcAS) & MaskSrcAS, CMP_EQ ),
										NewBlock(OffsetPort, MaskDstAS, ($3 << ShiftDstAS) & MaskDstAS, CMP_EQ)
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
									$$.self = NewBlock(OffsetSrcIP, $4, $$.ip & $4, CMP_EQ);
								} else if ( $$.direction == DESTINATION) {
									$$.self = NewBlock(OffsetDstIP, $4, $$.ip & $4, CMP_EQ);
								} else if ( $$.direction == SOURCE_OR_DESTINATION ) {
									$$.self = Connect_OR(
										NewBlock(OffsetSrcIP, $4, $$.ip & $4, CMP_EQ),
										NewBlock(OffsetDstIP, $4, $$.ip & $4, CMP_EQ)
									);
								} else if ( $$.direction == SOURCE_AND_DESTINATION ) {
									$$.self = Connect_AND(
										NewBlock(OffsetSrcIP, $4, $$.ip & $4, CMP_EQ),
										NewBlock(OffsetDstIP, $4, $$.ip & $4, CMP_EQ)
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


