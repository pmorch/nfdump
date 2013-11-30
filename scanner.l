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
 *  $Id: scanner.l 34 2005-08-22 12:01:31Z peter $
 *
 *  $LastChangedRevision: 34 $
 *	
 *
 *
 */

%{

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif


#include "nfdump.h"
#include "grammar.h"
int lineno = 1;

#ifdef FLEX_SCANNER
#define YY_NO_UNPUT
static YY_BUFFER_STATE in_buffer;
#else
static char *in_buffer;

#undef getc
#define getc(fp)  (*in_buffer == 0 ? EOF : *in_buffer++)
#endif

%}

N				[0-9]+
H				(0X|0x)[0-9A-Fa-f]+

%%

({N}{1,3}\.{N}{1,3})|({N}{1,3}\.{N}{1,3}\.{N}{1,3}) {
				  	yylval.s = strdup(yytext);
                  	return QUADDOT; 
				}
{N}{1,3}\.{N}{1,3}\.{N}{1,3}\.{N}{1,3} {
					yylval.s = strdup(yytext);
                  	return QUADDOT; 
				}
any				{ return ANY; }
ip				{ return IP; }
if				{ return IF; }
tcp				{ return TCP; }
udp				{ return UDP; }
gre				{ return GRE; }
esp				{ return ESP; }
ah				{ return AH; }
rsvp			{ return RSVP; }
proto			{ return PROTO; }
flags			{ return FLAGS; }
tos				{ return TOS; }
host			{ return HOST; }
net				{ return NET; }
icmp			{ return ICMP; }
port			{ return PORT; }
as				{ return AS; }
in				{ return IN; }
out				{ return OUT; }
next			{ return NEXT; }
packets			{ return PACKETS; }
bytes			{ return BYTES; }
bpp				{ return BPP; }
bps				{ return BPS; }
pps				{ return PPS; }
duration		{ return DURATION; }
and|"&&"		{ return AND; }
or|"||"			{ return OR; }
not|"!"			{ return NOT; }
"="|"=="|eq		{ return EQ; }
">"|gt			{ return GT; }
"<"|lt			{ return LT; }
src				{ return SRC; }
dst				{ return DST; }
#.*				{ ; }
[ \t]			{ ; }
[FSRPAUX]+		{ 
				  	yylval.s = strdup(yytext);
					return ALPHA_FLAGS;
				}
[0-9]+			{ 
					yylval.value = atoi(yytext); 
					return NUMBER;
				}
\n				{ lineno++; }
.				{ return yytext[0]; }
			
%%

void lex_init(char *buf) {
#ifdef FLEX_SCANNER
        in_buffer = yy_scan_string(buf);
#else
        in_buffer = buf;
#endif
}

/*
 * Do any cleanup necessary after parsing.
 */
void lex_cleanup(void) {
#ifdef FLEX_SCANNER
        if (in_buffer != NULL)
                yy_delete_buffer(in_buffer);
        in_buffer = NULL;
#endif
}

int yywrap(void) {
	return 1;
}
