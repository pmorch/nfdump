/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     ANY = 258,
     IP = 259,
     IF = 260,
     MAC = 261,
     MPLS = 262,
     TOS = 263,
     DIR = 264,
     FLAGS = 265,
     PROTO = 266,
     MASK = 267,
     HOSTNAME = 268,
     NET = 269,
     PORT = 270,
     FWDSTAT = 271,
     IN = 272,
     OUT = 273,
     SRC = 274,
     DST = 275,
     EQ = 276,
     LT = 277,
     GT = 278,
     PREV = 279,
     NEXT = 280,
     NUMBER = 281,
     STRING = 282,
     IDENT = 283,
     ALPHA_FLAGS = 284,
     PROTOSTR = 285,
     PORTNUM = 286,
     ICMP_TYPE = 287,
     ICMP_CODE = 288,
     ENGINE_TYPE = 289,
     ENGINE_ID = 290,
     AS = 291,
     PACKETS = 292,
     BYTES = 293,
     FLOWS = 294,
     PPS = 295,
     BPS = 296,
     BPP = 297,
     DURATION = 298,
     IPV4 = 299,
     IPV6 = 300,
     BGPNEXTHOP = 301,
     ROUTER = 302,
     VLAN = 303,
     CLIENT = 304,
     SERVER = 305,
     APP = 306,
     LATENCY = 307,
     SYSID = 308,
     NOT = 309,
     END = 310,
     OR = 311,
     AND = 312,
     NEGATE = 313
   };
#endif
/* Tokens.  */
#define ANY 258
#define IP 259
#define IF 260
#define MAC 261
#define MPLS 262
#define TOS 263
#define DIR 264
#define FLAGS 265
#define PROTO 266
#define MASK 267
#define HOSTNAME 268
#define NET 269
#define PORT 270
#define FWDSTAT 271
#define IN 272
#define OUT 273
#define SRC 274
#define DST 275
#define EQ 276
#define LT 277
#define GT 278
#define PREV 279
#define NEXT 280
#define NUMBER 281
#define STRING 282
#define IDENT 283
#define ALPHA_FLAGS 284
#define PROTOSTR 285
#define PORTNUM 286
#define ICMP_TYPE 287
#define ICMP_CODE 288
#define ENGINE_TYPE 289
#define ENGINE_ID 290
#define AS 291
#define PACKETS 292
#define BYTES 293
#define FLOWS 294
#define PPS 295
#define BPS 296
#define BPP 297
#define DURATION 298
#define IPV4 299
#define IPV6 300
#define BGPNEXTHOP 301
#define ROUTER 302
#define VLAN 303
#define CLIENT 304
#define SERVER 305
#define APP 306
#define LATENCY 307
#define SYSID 308
#define NOT 309
#define END 310
#define OR 311
#define AND 312
#define NEGATE 313




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 96 "grammar.y"
{
	uint64_t		value;
	char			*s;
	FilterParam_t	param;
	void			*list;
}
/* Line 1529 of yacc.c.  */
#line 172 "grammar.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

