/*
 *  nfprofile : Reads netflow data from files, saved by nfcapd
 *                      Data can be view, filtered and saved to 
 *                      files.
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
 *  $Id: profile.c 2 2004-09-20 18:12:36Z peter $
 *
 *  $LastChangedRevision: 2 $
 *      
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nfdump.h"
#include "util.h"
#include "nftree.h"
#include "profile.h"

static profileinfo_t *profile;
static unsigned int num_profiles;

static void SetupProfile(char *profiledir, char *profilename, char *subdir, char *filterfile, char *filename, int veryfy_only);

profileinfo_t	*GetProfiles(void) {
	return profile;
} // End of GetProfiles

int InitProfiles(char *profiledir, char *subdir, char *filterfile, char *filename, int veryfy_only ) {
DIR *PDIR;
struct dirent *entry;
struct stat stat_buf;
char	stringbuf[1024];

	profile 	 = NULL;
	num_profiles = 0;
	PDIR = opendir(profiledir);
	if ( !PDIR ) {
		perror("Can't read profiledir: ");
		return 0;
	}

	while ( ( entry = readdir(PDIR)) != NULL ) {
		snprintf(stringbuf, 1023, "%s/%s", profiledir, entry->d_name);
		if ( stat(stringbuf, &stat_buf) ) {
			perror("Can't stat entry: ");
			continue;
		}
		if ( !S_ISDIR(stat_buf.st_mode) ) 
			continue;

		// skip all '.' entries -> make .anything invisible to nfprofile
		if ( entry->d_name[0] == '.' )
			continue;

		SetupProfile(profiledir, entry->d_name, subdir, filterfile, filename, veryfy_only);
	}
	closedir(PDIR);

	return num_profiles;

} // End of InitProfiles

static void SetupProfile(char *profiledir, char *profilename, char *subdir, char *filterfile, char *filename, int veryfy_only) {
FilterEngine_data_t	*engine;
struct stat stat_buf;
char *filter;
char	stringbuf[1024];
int	ffd, wfd, ret;
short	*ftrue;

	// check if subdir exists if defined
	if ( subdir ) {
		snprintf(stringbuf, 1023, "%s/%s/%s", profiledir, profilename, subdir);
		if ( stat(stringbuf, &stat_buf) ) {
			fprintf(stderr, "Skipping directory '%s'\n", profilename);
			return;
		}
		if ( !S_ISDIR(stat_buf.st_mode) )
			return;
	} 


	// Try to read filter
	snprintf(stringbuf, 1023, "%s/%s/%s", profiledir, profilename, filterfile);
	if ( stat(stringbuf, &stat_buf) || !S_ISREG(stat_buf.st_mode) ) {
		fprintf(stderr, "Skipping directory '%s'\n", profilename);
		return;
	}

	// stringbuf contains filter file
	filter = (char *)malloc(stat_buf.st_size+1);
	if ( !filter ) {
		perror("Memory error: ");
		exit(255);
	}
	ffd = open(stringbuf, O_RDONLY);
	if ( ffd < 0 ) {
		fprintf(stderr, "Error opening file '%s': %s\n",stringbuf, strerror(errno) );
		perror("Can't open file");
		return;
	}

	ret = read(ffd, (void *)filter, stat_buf.st_size);
	if ( ret < 0   ) {
		perror("Error reading file");
		close(ffd);
		return;
	}
	close(ffd);
	filter[stat_buf.st_size] = 0;

	printf("Setup Profile %s\n", profilename);
	// compile profile filter
	if ( veryfy_only )
		printf("Check profile '%s': ", profilename);
			
	engine = CompileFilter(filter);
	free(filter);

	if ( !engine ) {
		printf("\n");
		exit(254);
	}

	if ( veryfy_only ) {
		printf("Done.\n");
		return;
	}

	// prepare output file
	if ( subdir )
		snprintf(stringbuf, 1023, "%s/%s/%s/%s", profiledir, profilename, subdir, filename);
	else 
		snprintf(stringbuf, 1023, "%s/%s/%s", profiledir, profilename, filename);

	wfd = open(stringbuf, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );

	if ( wfd < 0 ) {
		perror("Can't open file for writing");
		return;
	}

	// collect all profile info
	num_profiles++;
	profile = realloc(profile, num_profiles * sizeof(profileinfo_t) );
	ftrue   = (short *) malloc(BuffNumRecords * sizeof(short));
	if ( !profile || !ftrue) {
		perror("Memory error: ");
		exit(255);
	}

	memset(&profile[num_profiles-1], 0, sizeof(profileinfo_t));

	profile[num_profiles-1].engine		= engine;
	profile[num_profiles-1].name 		= strdup(profilename);
	profile[num_profiles-1].wfile 		= strdup(stringbuf);
	profile[num_profiles-1].wfd			= wfd;
	profile[num_profiles-1].first_seen	= 0xffffffff;
	profile[num_profiles-1].last_seen	= 0;
	profile[num_profiles-1].ftrue		= ftrue;

	return;

} // End of InitProfiles


void CloseProfiles (void) {
char sfile[255], tmpstring[64];
unsigned int num;
int	fd;

	for ( num = 0; num < num_profiles; num++ ) {

		close(profile[num].wfd);

		snprintf(sfile, 254, "%s.stat", profile[num].wfile);
		fd = open(sfile, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
		if ( fd == -1 ) {
			perror("Can't open stat file: ");
			continue;
		}
		
		snprintf(tmpstring, 64, "Time: %u\n", GetStatTime());
		write(fd, tmpstring, strlen(tmpstring)); 
		snprintf(tmpstring, 64, "Ident: %s\n", GetIdent());
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Flows: %llu\n", profile[num].numflows);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Flows_tcp: %llu\n", profile[num].numflows_tcp);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Flows_udp: %llu\n", profile[num].numflows_udp);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Flows_icmp: %llu\n", profile[num].numflows_icmp);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Flows_other: %llu\n", profile[num].numflows_other);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Packets: %llu\n", profile[num].numpackets);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Packets_tcp: %llu\n", profile[num].numpackets_tcp);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Packets_udp: %llu\n", profile[num].numpackets_udp);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Packets_icmp: %llu\n", profile[num].numpackets_icmp);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Packets_other: %llu\n", profile[num].numpackets_other);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Bytes: %llu\n", profile[num].numbytes);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Bytes_tcp: %llu\n", profile[num].numbytes_tcp);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Bytes_udp: %llu\n", profile[num].numbytes_udp);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Bytes_icmp: %llu\n", profile[num].numbytes_icmp);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Bytes_other: %llu\n", profile[num].numbytes_other);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "First: %u\n", profile[num].first_seen);
		write(fd, tmpstring, strlen(tmpstring));
		snprintf(tmpstring, 64, "Last: %u\n", profile[num].last_seen);
		write(fd, tmpstring, strlen(tmpstring));

		close(fd);
	}

} // End of CloseProfiles

