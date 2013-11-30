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
 *  $Id: util.c 41 2005-08-24 09:04:13Z peter $
 *
 *  $LastChangedRevision: 41 $
 *	
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "util.h"

#ifndef HAVE_SCANDIR 
int scandir(const char *dir, struct dirent ***namelist,
            const int (*select)(struct dirent *),
            const int (*compar)(const void *, const void *));

int alphasort(const void *a, const void *b);

#endif

/* Global vars */
// uint64_t	total_bytes = 0;

extern uint32_t	byte_limit, packet_limit;
extern int byte_mode, packet_mode;

enum { NONE, LESS, MORE };


/* Function prototypes */
static int check_number(char *s, int len);

static int ParseTime(char *s, time_t *t_start);

static int FileFilter(const struct dirent *dir);

static void ReadNetflowStat(char *sfile);

static void GetFileList(char *path);

static void GetDirList(char *dirs);

static time_t firstseen, lastseen;

typedef struct StatInfo_s {
	char 		Ident[32];
	uint32_t	tstamp;
	uint64_t	flows;
	uint64_t	flows_tcp;
	uint64_t	flows_udp;
	uint64_t	flows_icmp;
	uint64_t	flows_other;
	uint64_t	pkts;
	uint64_t	pkts_tcp;
	uint64_t	pkts_udp;
	uint64_t	pkts_icmp;
	uint64_t	pkts_other;
	uint64_t	bytes;
	uint64_t	bytes_tcp;
	uint64_t	bytes_udp;
	uint64_t	bytes_icmp;
	uint64_t	bytes_other;
	uint32_t	first_seen;
	uint32_t	last_seen;
} StatInfo_t;

static StatInfo_t	NetflowStat;

typedef struct DirList_s {
	struct DirList_s	*next;
	char				*dirname;
} DirList_t;


static struct dirent **namelist;
static DirList_t	*dirlist, *current_dir;
static uint32_t		numfiles, cnt;
static char			*first_file, *last_file;
static uint32_t		twin_first, twin_last;

/* Functions */

#ifndef HAVE_SCANDIR 
#include "scandir.c"
#endif

static int check_number(char *s, int len) {
int i;
int l = strlen(s);

	for ( i=0; i<l; i++ ) {
		if ( s[i] < '0' || s[i] > '9' ) {
			fprintf(stderr, "Time format error at '%s': unexpected character: '%c'.\n", s, s[i]);
			return 0;
		}
	}

	if ( l != len ) {
		fprintf(stderr, "Time format error: '%s' unexpected.\n", s);
		return 0;
	}
	return 1;

} // End of check_number

static int ParseTime(char *s, time_t *t_start ) {
struct tm ts;
int	i;
char *p, *q;


	/* A time string may look like:
	 * yyyy/MM/dd.hh:mm:ss
	 */

	memset((void *)&ts, 0, sizeof(ts));
	ts.tm_isdst = -1;

	p = s;

	// parse year
	q = strchr(p, '/');
	if ( q ) {
		*q++ = 0;
	}
	if ( !check_number(p,4) )
		return 0;
	i = atoi(p);
	if ( i > 2013 || i < 1970 ) {
		fprintf(stderr, "Year out of range: '%i'\n", i);
		*t_start = 0;
		return 0;
	}
	ts.tm_year = i - 1900;
	if ( !q ) {
		ts.tm_mday = 1;
		*t_start = mktime(&ts);
		return 1;
	}

	// parse month
	p = q;
	q = strchr(p, '/');
	if ( q ) 
		*q++ = 0;
	if ( !check_number(p,2) ) 
		return 0;
	i = atoi(p);
	if ( i < 1 || i > 12 ) {
		fprintf(stderr, "Month out of range: '%i'\n", i);
		*t_start = 0;
		return 0;
	}
	ts.tm_mon = i - 1;
	if ( !q ) {
		ts.tm_mday = 1;
		*t_start   = mktime(&ts);
		return 1;
	}

	// Parse day
	p = q;
	q = strchr(p, '.');
	if ( q ) 
		*q++ = 0;
	if ( !check_number(p,2) ) 
		return 0;
	i = atoi(p);
	if ( i < 1 || i > 31 ) {
		fprintf(stderr, "Day out of range: '%i'\n", i);
		*t_start = 0;
		return 0;
	}
	ts.tm_mday = i;
	if ( !q ) {
		*t_start = mktime(&ts);
		return 1;
	}

	// Parse hour
	p = q;
	q = strchr(p, ':');
	if ( q ) 
		*q++ = 0;
	if ( !check_number(p,2) ) 
		return 0;
	i = atoi(p);
	if ( i < 0 || i > 23 ) {
		fprintf(stderr, "Hour out of range: '%i'\n", i);
		*t_start = 0;
		return 0;
	}
	ts.tm_hour = i;
	if ( !q ) {
		*t_start = mktime(&ts);
		return 1;
	}

	// Parse minute
	p = q;
	q = strchr(p, ':');
	if ( q ) 
		*q++ = 0;
	if ( !check_number(p,2) ) 
		return 0;
	i = atoi(p);
	if ( i < 0 || i > 59 ) {
		fprintf(stderr, "Minute out of range: '%i'\n", i);
		*t_start = 0;
		return 0;
	}
	ts.tm_min = i;
	if ( !q ) {
		*t_start = mktime(&ts);
		return 1;
	}

	// Parse second
	p = q;
	if ( !check_number(p,2) ) 
		return 0;
	i = atoi(p);
	if ( i < 0 || i > 59 ) {
		fprintf(stderr, "Seconds out of range: '%i'\n", i);
		*t_start = 0;
		return 0;
	}
	ts.tm_sec = i;
	*t_start = mktime(&ts);
	return 1;

} // End of ParseTime


int ScanTimeFrame(char *tstring, time_t *t_start, time_t *t_end) {
char *p;

	if ( !tstring ) {
		fprintf(stderr,"Time Window format error '%s'\n", tstring);
		return 0;
	}

	// check for delta time window
	if ( tstring[0] == '-' || tstring[0] == '+' ) {
		if ( !twin_first || !twin_last ) {
			fprintf(stderr,"Time Window error: Check if stat files available\n");
			return 0;
		}

		if ( tstring[0] == '-' ) {
			*t_start = twin_last + atoi(tstring);
			*t_end	 = twin_last;
			return 1;
		}
		
		if ( tstring[0] == '+' ) {
			*t_start = twin_first;
			*t_end	 = twin_first + atoi(tstring);
			return 1;
		}
	}

	if ( strlen(tstring) < 4 ) {
		fprintf(stderr,"Time Window format error '%s'\n", tstring);
		return 0;
	}
	if ( (p = strchr(tstring, '-') ) == NULL ) {
		ParseTime(tstring, t_start);
		*t_end = 0xFFFFFFFF;
	} else {
		*p++ = 0;
		ParseTime(tstring, t_start);
		ParseTime(p, t_end);
	}

	return *t_start == 0 || *t_end == 0 ? 0 : 1;

} // End of ScanTimeFrame

static void ReadNetflowStat(char *sfile){
FILE *fd;

	if ( sfile == NULL ) {
	// printf("No Statfile\n");
		NetflowStat.Ident[0] 	= 0;
		NetflowStat.first_seen  = 0;
		NetflowStat.last_seen	= 0;
	}

	// printf("Statfile %s\n",sfile);
	fd = fopen(sfile, "r");
	if ( !fd ) {
		NetflowStat.Ident[0] 	= 0;
		NetflowStat.first_seen = 0;
		NetflowStat.last_seen	= 0;
	// printf("No such Statfile\n");
		return;
	}
	// printf("Statfile ok\n");
	fscanf(fd, "Time: %u\n", &NetflowStat.tstamp);
	fscanf(fd, "Ident: %s\n", NetflowStat.Ident); 
	fscanf(fd, "Flows: %llu\n", &NetflowStat.flows);
	fscanf(fd, "Flows_tcp: %llu\n", &NetflowStat.flows_tcp);
	fscanf(fd, "Flows_udp: %llu\n", &NetflowStat.flows_udp);
	fscanf(fd, "Flows_icmp: %llu\n", &NetflowStat.flows_icmp);
	fscanf(fd, "Flows_other: %llu\n", &NetflowStat.flows_other);
	fscanf(fd, "Packets: %llu\n", &NetflowStat.pkts);
	fscanf(fd, "Packets_tcp: %llu\n", &NetflowStat.pkts_tcp);
	fscanf(fd, "Packets_udp: %llu\n", &NetflowStat.pkts_udp);
	fscanf(fd, "Packets_icmp: %llu\n", &NetflowStat.pkts_icmp);
	fscanf(fd, "Packets_other: %llu\n", &NetflowStat.pkts_other);
	fscanf(fd, "Bytes: %llu\n", &NetflowStat.bytes);
	fscanf(fd, "Bytes_tcp: %llu\n", &NetflowStat.bytes_tcp);
	fscanf(fd, "Bytes_udp: %llu\n", &NetflowStat.bytes_udp);
	fscanf(fd, "Bytes_icmp: %llu\n", &NetflowStat.bytes_icmp);
	fscanf(fd, "Bytes_other: %llu\n", &NetflowStat.bytes_other);
	fscanf(fd, "First: %u\n", &NetflowStat.first_seen);
	fscanf(fd, "Last: %u\n", &NetflowStat.last_seen);
	fclose(fd);

/*
	printf("Time: %u\n", NetflowStat.tstamp);
	printf("Ident: %s\n", NetflowStat.Ident);
	printf("Flows: %llu\n", NetflowStat.flows);
	printf("Flows_tcp: %llu\n", NetflowStat.flows_tcp);
	printf("Flows_udp: %llu\n", NetflowStat.flows_udp);
	printf("Flows_icmp: %llu\n", NetflowStat.flows_icmp);
	printf("Flows_other: %llu\n", NetflowStat.flows_other);
	printf("Packets: %llu\n", NetflowStat.pkts);
	printf("Packets_tcp: %llu\n", NetflowStat.pkts_tcp);
	printf("Packets_udp: %llu\n", NetflowStat.pkts_udp);
	printf("Packets_icmp: %llu\n", NetflowStat.pkts_icmp);
	printf("Packets_other: %llu\n", NetflowStat.pkts_other);
	printf("Bytes: %llu\n", NetflowStat.bytes);
	printf("Bytes_tcp: %llu\n", NetflowStat.bytes_tcp);
	printf("Bytes_udp: %llu\n", NetflowStat.bytes_udp);
	printf("Bytes_icmp: %llu\n", NetflowStat.bytes_icmp);
	printf("Bytes_other: %llu\n", NetflowStat.bytes_other);
	printf("First: %u\n", NetflowStat.first_seen);
	printf("Last: %u\n", NetflowStat.last_seen);
*/

} // End of ReadNetflowStat

char *GetIdent(void) {

	return strlen(NetflowStat.Ident) > 0 ? NetflowStat.Ident : "none";

} // End of GetIdent

uint32_t GetStatTime(void) {

	return NetflowStat.tstamp;

} // End of GetIdent

char *TimeString(void){
static char datestr[255];
char t1[64], t2[64];
struct tm	*tbuff;

	if ( firstseen ) {
		tbuff = localtime(&firstseen);
		if ( !tbuff ) {
			perror("Error time convert");
			exit(250);
		}
		strftime(t1, 63, "%b %d %Y %T", tbuff);

		tbuff = localtime(&lastseen);
		if ( !tbuff ) {
			perror("Error time convert");
			exit(250);
		}
		strftime(t2, 63, "%b %d %Y %T", tbuff);

		snprintf(datestr, 254, "%s - %s", t1, t2);
	} else {
		snprintf(datestr, 254, "Time Window unknown");
	}
	datestr[254] = 0;
	return datestr;
}

int CheckTimeWindow(uint32_t t_start, uint32_t t_end) {
/*
	printf("t start %u %s", t_start, ctime(&t_start));
	printf("t end   %u %s", t_end, ctime(&t_end));
	printf("f start %u %s", NetflowStat.first_seen, ctime(&NetflowStat.first_seen));
	printf("f end   %u %s", NetflowStat.last_seen, ctime(&NetflowStat.last_seen));
*/

	// if no time window is set, return true
	if ( t_start == 0 )
		return 1;

	if ( NetflowStat.first_seen == 0 )
		return 0;

	if ( t_start >= NetflowStat.first_seen  && t_start <= NetflowStat.last_seen ) 
		return 1;

	if ( t_end >= NetflowStat.first_seen  && t_end <= NetflowStat.last_seen ) 
		return 1;

	if ( t_start < NetflowStat.first_seen  && t_end > NetflowStat.last_seen ) 
		return 1;


	return 0;

} // End of CheckTimeWindow

void SetSeenTwin(uint32_t first_seen, uint32_t last_seen) {
	firstseen = first_seen;
	lastseen  = last_seen;

} /* End of SetSeenTwin */

// file filter for scandir function

static	int FileFilter(const struct dirent *dir) {
struct stat stat_buf;
char string[255];

	string[254] = 0;
	snprintf(string, 254, "%s/%s", dirlist->dirname, dir->d_name);
	if ( stat(string, &stat_buf) ) {
		perror("Can't stat entry: ");
		return 0;
	}

	// 	if it's not a file
	if ( !S_ISREG(stat_buf.st_mode) ) {
		return 0;
	}
	// mask out all stat files
	if ( strstr(dir->d_name, ".stat") ) 
		return 0;

	// mask out tmp file of nfcapd
	if ( strstr(dir->d_name, "nfcapd.current") ) 
		return 0;

	if ( first_file ) {
		if ( last_file ) {
			return ( strcmp(dir->d_name, first_file) >= 0 ) && ( strcmp(dir->d_name, last_file) <= 0 );
		} else {
			return strcmp(dir->d_name, first_file) >= 0;
		}
	} else {
		if ( last_file ) {
			return strcmp(dir->d_name, last_file) <= 0;
		} else {
			return 1;
		}
	}

} // End of FileFilter

/*
 * path my contain:
 * 		/path/to/dir/firstfile:lastfile
 * 		/path/to/dir/firstfile
 * 		/path/to/dir
 *		firstfile:lastfile
 *		firstfile
 *		dir
 * dirpath is set to the directory containing all the files
 * first_file and last_file may contain filenames, that limit the file list
 *
 */
static void GetFileList(char *path) {
struct stat stat_buf;
char *p, *q, *dirpath, string[512];

	
	// set dirpath to the directory containing all the files
	// this may also come from the dirlist, if set
	// Note: Only the first dir in dirlist counts as it is assumed
	// all the other dirs contain the same files
	p = strrchr(path, '/');
	if ( p ) {
		if ( dirlist ) {
			// make sure we have no directory path in -R <filelist>
			// when using multiple directories option -M
			fprintf(stderr, "File name error: -R <filelist> must not contain a directory name\n");
			fprintf(stderr, "when using with -M multiple directory option\n");
			exit(250);
		} else {
			*p++ = 0;
			dirpath = path;
		}
	} else {
		dirpath = dirlist ? dirlist->dirname : ".";
		p = path;
	}
	// dirpath is set 
	// p contains rest of string to analyze:
	// 		firstfile:lastfile
	// 		firstfile
	// 		dir

	first_file = last_file = NULL;

	if ( ( q = strchr(p, ':')) != NULL  ) {
		// we have firstfile:lastfile 
		*q++ = 0;
		last_file  = q;
		first_file = p;
		if ( strlen(first_file) == 0 || strlen(last_file) == 0 ) {
			fprintf(stderr, "Missing file.\n");
			exit(250);
		}

	} else {
		// p is either a directory or a file
		snprintf(string, 510, "%s/%s", dirpath, p);
		string[511] = 0;
		if ( stat(string, &stat_buf) ) {
			fprintf(stderr, "Can't stat '%s': %s\n", string, strerror(errno));
			return;
		}

		// it's a dir
		if ( S_ISDIR(stat_buf.st_mode) ) {
			if ( dirlist && (strcmp(path, ".") != 0) ) { 
				fprintf(stderr, "File name error: -R <filelist> must not contain a directory name\n");
				fprintf(stderr, "when using with -M multiple directory option\n");
				exit(250);
			}

			// append dir to dirpath
			dirpath = strdup(string);

		// it's a file
		} else if (S_ISREG(stat_buf.st_mode) ) {
			first_file = p;

		// it's something else
		} else {
			fprintf(stderr, "Not a file or directory: '%s'\n", string);
			exit(250);
		}

		if ( !dirpath ) {
			// should never happen, unless out of memory, when strdup is called!
			fprintf(stderr, "Dirpath NULL\n");
			exit(250);
		}
	}

	// make sure we have at least one entry in the dirlist
	// so subsequent functions do not have to care any more
	// if multiple dirs or files or whatever ...
	if ( !dirlist ) {
		dirlist = (DirList_t *)malloc(sizeof(DirList_t));
		if ( !dirlist ) {
			perror("GetDirList failed!");
			exit(250);
		}
		dirlist->dirname = strdup(dirpath);
		dirlist->next	 = NULL;
	}

	// sanity checks
	if ( first_file ) {
		snprintf(string, 254, "%s/%s", dirlist->dirname, first_file);
		string[254] = '0';
		if ( stat(string, &stat_buf) ) {
			fprintf(stderr, "Can't stat file '%s': %s\n", string, strerror(errno));
			return;
		}
		if (!S_ISREG(stat_buf.st_mode) ) {
			fprintf(stderr, "'%s' is not a file\n", string);
			return;
		}
	}
	if ( last_file ) {
		snprintf(string, 254, "%s/%s", dirlist->dirname, last_file);
		string[254] = '0';
		if ( stat(string, &stat_buf) ) {
			fprintf(stderr, "Can't stat file '%s': %s\n", string, strerror(errno));
			return;
		}
		if (!S_ISREG(stat_buf.st_mode) ) {
			fprintf(stderr, "'%s' is not a file\n", string);
			return;
		}

	}

	// scan the directory
	numfiles = scandir(dirpath, &namelist, FileFilter, alphasort);

} // End of GetFileList

/*
 * Get the list of directories 
 * dirs: user supplied parameter: /any/path/dir1:dir2:dir3:...
 * 		dirlist must result in 
 * 		/any/path/dir1
 * 		/any/path/dir2
 * 		/any/path/dir3
 * 	/any/path is dir prefix, which may be NULL e.g. dir1:dir2:dir3:...
 * 	dir1, dir2 etc dirnames
 */
void GetDirList(char *dirs) {
struct stat stat_buf;
char	*p, *q, *dirprefix;
char	path[1024];
DirList_t	**list;

	list = &dirlist;
	q = strchr(dirs, ':');
	if ( q ) { // we have /path/to/firstdir:dir1:dir2:...
		*q = 0;
		p = strrchr(dirs, '/');
		if ( p ) {
			*p++ = 0;	// p points now to the first name in the dir list
			dirprefix = dirs;
		} else  { // we have a dirlist in current directory
			p = dirs;	// p points now to the first name in the dir list
			dirprefix = ".";	// current directory
		}
		*q = ':';	// restore ':' in dirlist

		while ( p ) { // iterate over all elements in the dir list
			q = strchr(p, ':');
			if ( q ) 
				*q = 0;

			// p point to a dir name
			snprintf(path, 1023, "%s/%s", dirprefix, p);
			path[1023] = 0;
			if ( stat(dirs, &stat_buf) ) {
				fprintf(stderr, "Can't stat '%s': %s\n", path, strerror(errno));
				dirlist = NULL;
				return;
			}
			if ( !S_ISDIR(stat_buf.st_mode) ) {
				fprintf(stderr, "Not a directory: '%s'\n", path);
				dirlist = NULL;
				return;
			}
			// save path into dirlist
			*list = (DirList_t *)malloc(sizeof(DirList_t));
			if ( !*list ) {
				perror("GetDirList failed!");
				exit(250);
			}
			(*list)->dirname = strdup(path);
			(*list)->next	 = NULL;
			list = &((*list)->next);
			p = q ? q + 1 : NULL;
		}

	} else { // we have only one directory
		dirlist = NULL;
		if ( stat(dirs, &stat_buf) ) {
			fprintf(stderr, "Can't stat '%s': %s\n", dirs, strerror(errno));
			return;
		}
		if ( !S_ISDIR(stat_buf.st_mode) ) {
			fprintf(stderr, "Not a directory: '%s'\n", dirs);
			return;
		}
		dirlist = (DirList_t *)malloc(sizeof(DirList_t));
		if ( !dirlist ) {
			perror("GetDirList failed!");
			exit(250);
		}
		dirlist->dirname = strdup(dirs);
		dirlist->next	 = NULL;
	}

} // End of GetDirList

void SetupInputFileSequence(char *multiple_dirs, char *single_file, char *multiple_files) {
char string[255];
char *p;

	namelist    = NULL;
	twin_first  = 0;
	twin_last   = 0xffffffff;

	if ( multiple_dirs ) 
		GetDirList(multiple_dirs);

	if ( multiple_files ) {
		// use multiple files
		numfiles   = 0;
		GetFileList(multiple_files);

		// get time window spanning all the files 
		if ( numfiles ) {
			snprintf(string, 254, "%s/%s.stat", dirlist->dirname, namelist[0]->d_name);
			ReadNetflowStat(string);	// read the corresponding stat file
			twin_first = NetflowStat.first_seen;
			snprintf(string, 254, "%s/%s.stat", dirlist->dirname, namelist[numfiles-1]->d_name);
			ReadNetflowStat(string);	// read the corresponding stat file
			twin_last  = NetflowStat.last_seen;
		}

	} else if ( single_file ) {
		if ( dirlist && strchr(single_file, '/') ) {
			fprintf(stderr, "File name error: -r <file> must not contain a directory name\n");
			fprintf(stderr, "when using with -M multiple directory option\n");
			exit(250);
		}
		// printf("Set single %s\n", single_file);
		// Normalize the lists:
		// if we have no dirlist, make one with a single entry
		// and store the directory part in dirlist
		namelist = ( struct dirent **)malloc(sizeof(struct dirent *));
		if ( !namelist ) {
			perror("GetDirList failed!");
			exit(250);
		}
		*namelist = ( struct dirent *)malloc(sizeof(struct dirent ));
		if ( !*namelist ) {
			perror("GetDirList failed!");
			exit(250);
		}

		if ( !dirlist ) {
			dirlist = (DirList_t *)malloc(sizeof(DirList_t));
			if ( !dirlist ) {
				perror("GetDirList failed!");
				exit(250);
			}
			dirlist->next	 = NULL;

			p = strrchr(single_file, '/');
			if ( p ) {
				*p++ = 0;
				dirlist->dirname = strdup(single_file);
			} else {
				dirlist->dirname = ".";
				p = single_file;
			}
			strncpy(namelist[0]->d_name, p, 255);
			(namelist[0]->d_name)[255] = 0;
		} else {
			strncpy(namelist[0]->d_name, single_file, 255);
			(namelist[0]->d_name)[255] = 0;
		}
		numfiles   = 1;

	} else {
		// use stdin
		// dirlist == NULL
		numfiles   = 1;
	}

	// set first directory to current dir
	cnt 		= 0;
	current_dir = dirlist;
	
	/*
	for ( current_dir = dirlist; current_dir != NULL; current_dir = current_dir->next ) {
		fprintf(stderr, "Dirlist: '%s'\n", current_dir->dirname);
	}
	fprintf(stderr, "\n");
	for ( i = 0; i < numfiles; i++ ) {
		fprintf(stderr, "File: '%s'\n", namelist[i]->d_name);
	}
	current_dir = dirlist;
	*/

} // End of SetupInputFileSequence

int GetNextFile(int current, time_t twin_start, time_t twin_end) {
struct stat stat_buf;
char string[255], *fname;
int stat_failed;

	// close current file before open the next one
	// stdin ( current = 0 ) is not closed
	if ( current )
		close(current);

	// no or no more files available
	if ( (numfiles == 0) ) {
		errno = 0;
		return -1;
	}
	
	if ( dirlist == NULL ) {
		// use stdin
		//	printf("Return stdin\n");
		numfiles = 0;
		return STDIN_FILENO;
	}

	while ( cnt < numfiles ) {
		while ( current_dir ) {
			fname = namelist[cnt]->d_name;
			snprintf(string, 254, "%s/%s.stat", current_dir->dirname, fname);
			ReadNetflowStat(string);	// read the corresponding stat file
			if ( CheckTimeWindow(twin_start, twin_end) ) {
				snprintf(string, 254, "%s/%s", current_dir->dirname, fname);
				stat_failed = 0;
				if ( stat(string, &stat_buf) ) {
					fprintf(stderr, "Can't stat '%s': %s\n", string, strerror(errno));
					stat_failed = 1;
				}
				if (!S_ISREG(stat_buf.st_mode) ) {
					fprintf(stderr, "'%s' is not a file\n", string);
					stat_failed = 1;
				}
				// total_bytes += stat_buf.st_size;
				// printf("Return file: %s\n", string);
				current_dir = current_dir->next;
				if ( !stat_failed ) 
					return open(string, O_RDONLY);
			} 
			// in the event of missing the stat file in the last directory
			// of the directory queue current_dir is already NULL
			current_dir = current_dir ? current_dir->next : NULL;
		} 
		cnt++;
		current_dir = dirlist;
	}


	errno = 0;
	return -1;

} // End of GetNextFile

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

void UpdateTimeWindow ( time_t *start, time_t *end ) {

	if ( NetflowStat.first_seen < *start ) 
		*start = NetflowStat.first_seen;
	if ( NetflowStat.last_seen > *end ) 
		*end = NetflowStat.last_seen;

} // End of UpdateTimeWindow
