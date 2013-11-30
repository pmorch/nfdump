/*
 *  nfcapd : Reads netflow data from socket and saves the
 *  data into a file. The file gets automatically rotated
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
 *  $Id: nfcapd.c 53 2005-11-17 07:45:34Z peter $
 *
 *  $LastChangedRevision: 53 $
 *	
 *
 */

/*
 * Because NetFlow export uses UDP to send export datagrams, it is possible 
 * for datagrams to be lost. To determine whether flow export information has 
 * been lost, Version 5, Version 7, and Version 8 headers contain a flow 
 * sequence number. The sequence number is equal to the sequence number of the 
 * previous datagram plus the number of flows in the previous datagram. After 
 * receiving a new datagram, the receiving application can subtract the expected 
 * sequence number from the sequence number in the header to derive the number 
 * of missed flows.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <sys/mman.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "version.h"
#include "nf_common.h"
#include "launch.h"
#include "netflow_v5.h"
#include "netflow_v7.h"

#define DEFAULTCISCOPORT 9995
#define TIME_WINDOW	  	300 		// The Default Time Window is 5min
#define OVERDUE_TIME	20			// Rename File latest, after end of time window
#define DEFAULT_DIR	  	"/var/tmp"

#define BUFFSIZE 655350
#define NF_DUMPFILE "nfcapd.current"

#define delta(a,b) ( (a)>(b) ? (a)-(b) : (b)-(a) )

#define SYSLOG_FACILITY LOG_DAEMON

/* Global Variables */
uint32_t	byte_limit, packet_limit;	// needed for linking purpose only
int 		byte_mode, packet_mode;
caddr_t		shmem;

/*
 * local static vars used by interrupt routine
 */
static int done, launcher_alive, rename_trigger, launcher_pid, verbose = 0;
static char Ident[32];

static char const *rcsid 		  = "$Id: nfcapd.c 53 2005-11-17 07:45:34Z peter $";

/* Function Prototypes */
static void IntHandler(int signal);

static void usage(char *name);

static void SetPriv(char *userid, char *groupid );

static int Setup_Socket(char *IPAddr, int portnum, int sockbuflen );

static void kill_launcher(int pid);

void kill_launcher(int pid) {
int stat;

	if ( pid == 0 )
		return;

	if ( launcher_alive ) {
		kill(pid, SIGTERM);
		waitpid (pid, &stat, 0);
		syslog(LOG_INFO, "laucher terminated: %i", stat);
	} else {
		waitpid (pid, &stat, 0);
		syslog(LOG_ERR, "Can't terminate laucher: process already did: %i", stat);
	}

} // End of kill_launcher


static void run(int socket, unsigned int bufflen, time_t twin, time_t t_begin, int report_seq);

/* Functions */
static void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tthis text you see right here\n"
					"-u userid\tChange user to userid\n"
					"-g groupid\tChange group to groupid\n"
					"-w\t\tSync file rotation with next 5min (default) interval\n"
					"-t interval\tset the interval to rotate nfcapd files\n"
					"-b ipaddr\tbind socket to IP addr\n"
					"-p portnum\tlisten on port portnum\n"
					"-l logdir \tset the output directory. (default /var/tmp) \n"
					"-I Ident\tset the ident string for stat file. (default 'none')\n"
					"-P pidfile\tset the PID file\n"
					"-r\t\tReport missing flows to syslog\n"
					"-x process\tlauch process after a new file becomes available\n"
					"-B bufflen\tSet socket buffer to bufflen bytes\n"
					"-D\t\tFork to background\n"
					"-E\t\tPrint extended format of netflow data. for debugging purpose only.\n"
					"-V\t\tPrint version and exit.\n"
					, name);
} /* usage */

static void IntHandler(int signal) {

	switch (signal) {
		case SIGALRM:
			rename_trigger = 1;
			break;
		case SIGHUP:
		case SIGINT:
		case SIGTERM:
			done = 1;
			break;
		case SIGCHLD:
			launcher_alive = 0;
			break;
		default:
			// ignore everything we don't know
			break;
	}

} /* End of IntHandler */

static void SetPriv(char *userid, char *groupid ) {
struct 	passwd *pw_entry;
struct 	group *gr_entry;
uid_t	myuid, newuid, newgid;
int		err;

	if ( userid == 0 && groupid == 0 )
		return;

	newuid = newgid = 0;
	myuid = getuid();
	if ( myuid != 0 ) {
		syslog(LOG_ERR, "Only root wants to change uid/gid");
		fprintf(stderr, "ERROR: Only root wants to change uid/gid\n");
		exit(255);
	}

	if ( userid ) {
		pw_entry = getpwnam(userid);
		newuid = pw_entry ? pw_entry->pw_uid : atol(userid);

		if ( newuid == 0 ) {
			fprintf (stderr,"Invalid user '%s'\n", userid);
			exit(255);
		}
	}

	if ( groupid ) {
		gr_entry = getgrnam(groupid);
		newgid = gr_entry ? gr_entry->gr_gid : atol(groupid);

		if ( newgid == 0 ) {
			fprintf (stderr,"Invalid group '%s'\n", groupid);
			exit(255);
		}

		err = setgid(newgid);
		if ( err ) {
			syslog(LOG_ERR, "Can't set group id %u for group '%s': %s", newgid, groupid, strerror(errno));
			fprintf (stderr,"Can't set group id %u for group '%s': %s\n", newgid, groupid, strerror(errno));
			exit(255);
		}

	}

	if ( newuid ) {
		err = setuid(newuid);
		if ( err ) {
			syslog(LOG_ERR, "Can't set user id %u for user '%s': %s", newuid, userid, strerror(errno));
			fprintf (stderr,"Can't set user id %u for user '%s': %s\n", newuid, userid, strerror(errno));
			exit(255);
		}
	}

} // End of SetPriv

static int Setup_Socket(char *IPAddr, int portnum, int sockbuflen ) {
struct sockaddr_in server;
int s, p;
socklen_t	   optlen;


	if ( !portnum ) 
		portnum = DEFAULTCISCOPORT;

	s = socket (AF_INET, SOCK_DGRAM, 0);
	if ( s < 0 ) {
		fprintf(stderr, "Can't open socket: %s\n", strerror(errno));
		syslog(LOG_ERR, "Can't open socket: %s", strerror(errno));
		return -1;
	}

	memset ((char *) &server, 0, sizeof (server));

	server.sin_addr.s_addr = IPAddr ? inet_addr(IPAddr) : INADDR_ANY;
	server.sin_family = AF_INET;
	server.sin_port = htons(portnum);

	if ( (bind (s, (struct sockaddr *)&server, sizeof(server))) < 0 ) {
		fprintf(stderr, "bind to %s:%i failed: %s\n", inet_ntoa(server.sin_addr), portnum, strerror(errno));
		syslog(LOG_ERR, "bind to %s:%i failed: %s", inet_ntoa(server.sin_addr), portnum, strerror(errno));
		close(s);
		return -1;
	}

	if ( sockbuflen ) {
		optlen = sizeof(p);
		getsockopt(s,SOL_SOCKET,SO_RCVBUF,&p,&optlen);
		syslog(LOG_INFO,"Standard setsockopt, SO_RCVBUF is %i Requested length is %i bytes",p, sockbuflen);
		if ((setsockopt(s, SOL_SOCKET, SO_RCVBUF, &sockbuflen, sizeof(sockbuflen)) != 0) ) {
			fprintf (stderr, "setsockopt(SO_RCVBUF,%d): %s\n", sockbuflen, strerror (errno));
			syslog (LOG_ERR, "setsockopt(SO_RCVBUF,%d): %s", sockbuflen, strerror (errno));
			close(s);
			return -1;
		} else {
			getsockopt(s,SOL_SOCKET,SO_RCVBUF,&p,&optlen);
			syslog(LOG_INFO,"System set setsockopt, SO_RCVBUF to %d bytes", p);
		}
	} 

	return s;

}  /* End of Setup_Socket */


static void run(int socket, unsigned int bufflen, time_t twin, time_t t_begin, int report_seq) {
size_t writesize;
ssize_t	cnt;
netflow_v5_header_t	*nf_header_in;			// v5/v7 common header
netflow_v5_record_t *v5_record;
flow_header_t 		*nf_header_out;			// file flow header
flow_record_t		*nf_record_out;			// file flow record
time_t 		t_start, t_now;
uint32_t	buffsize;
uint64_t	numflows, numbytes, numpackets;
uint64_t	numflows_tcp, numflows_udp, numflows_icmp, numflows_other;
uint64_t	numbytes_tcp, numbytes_udp, numbytes_icmp, numbytes_other;
uint64_t	numpackets_tcp, numpackets_udp, numpackets_icmp, numpackets_other;
uint64_t	start_time, end_time, boot_time, first_seen, last_seen;
uint32_t	First, Last, sequence_failure, bad_packets;
int64_t		last_sequence, sequence, distance, last_count;
struct  tm *now;
void 		*in_buff, *out_buff, *p, *q;
int 		i, err, nffd, header_length, record_length, first;
char 		*string, tmpstring[64];
srecord_t	*commbuff;

	if ( !bufflen || bufflen < BUFFSIZE ) 
		bufflen = BUFFSIZE;

	in_buff  = malloc(bufflen);
	out_buff = malloc(bufflen);
	if ( !in_buff || !out_buff ) {
		syslog(LOG_ERR, "Buffer allocation error: %s", strerror(errno));
		return;
	}

	// init vars
	commbuff = (srecord_t *)shmem;

	p = in_buff;
	q = out_buff;
	cnt = 0;
	nf_header_in  = NULL;
	nf_header_out = NULL;
	v5_record     = NULL;
	nf_record_out = NULL;
	header_length = NETFLOW_V5_HEADER_LENGTH;	// v5 and v7 have same length

	nffd = open(NF_DUMPFILE, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
	if ( nffd == -1 ) {
		syslog(LOG_ERR, "Can't open file: '%s': %s", NF_DUMPFILE, strerror(errno));
		return;
	}

	bad_packets		 = 0;

	// init sequence check vars 
	last_sequence 	 = 0;
	sequence 		 = 0;
	distance 		 = 0;
	last_count 		 = 0;
	sequence_failure = 0;
	first			 = 1;

	first_seen = (uint64_t)0xffffffffffffLL;
	last_seen = 0;
	t_start = t_begin;
	numflows = numbytes = numpackets = buffsize = 0;
	numflows_tcp = numflows_udp = numflows_icmp = numflows_other = 0;
	numbytes_tcp = numbytes_udp = numbytes_icmp = numbytes_other = 0;
	numpackets_tcp = numpackets_udp = numpackets_icmp = numpackets_other = 0;

	rename_trigger = 0;
	alarm(t_start + twin + OVERDUE_TIME - time(NULL));
	// convert all v7 records to v5 records while processing them
	// this ignores the router_sc field in v7
	while ( !done ) {
		/* check for too little data */
		if ( buffsize > 0 && buffsize < header_length ) {
			syslog(LOG_WARNING, "Data length error: too little data for netflow v5 header: %i", buffsize);
			buffsize = 0;
			p = in_buff;
			q = out_buff;
			bad_packets++;
			continue;
		}
		/* read next bunch of data into beginn of input buffer */
		if ( buffsize == 0 ) {
			cnt = recv (socket, in_buff, bufflen , 0);
			buffsize = cnt > 0 ? cnt : 0;
			p = in_buff;
			q = out_buff;
			/* check for too little data */
			if ( buffsize > 0 && buffsize < header_length ) {
				syslog(LOG_WARNING, "Data length error: too little data for netflow header: %i", buffsize);
				buffsize = 0;
				p = in_buff;
				q = out_buff;
				bad_packets++;
				continue;
			}
		}
		/* paranoia check */
		if ( ( (pointer_addr_t)p - (pointer_addr_t)in_buff ) > bufflen ) {
			/* should never happen, but catch it anyway */
			syslog(LOG_ERR, "Buffer space error");
			buffsize = 0;
			p = in_buff;
			q = out_buff;
			continue;
		}

		/* File renaming */
		t_now = time(NULL);
		if ( ((t_now - t_start) >= twin) || done ) {
			alarm(0);
			now = localtime(&t_start);
			snprintf(tmpstring, 64, "nfcapd.%i%02i%02i%02i%02i", 
				now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min);
			close(nffd);
			err = rename(NF_DUMPFILE, tmpstring);
			if ( err ) {
				syslog(LOG_ERR, "Can't rename dump file: %s", strerror(errno));
				continue;
			}
			if ( launcher_pid ) {
				strncpy(commbuff->fname, tmpstring, FNAME_SIZE);
				commbuff->fname[FNAME_SIZE-1] = 0;
				snprintf(commbuff->tstring, 16, "%i%02i%02i%02i%02i", 
					now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min);
				commbuff->tstring[15] = 0;
				commbuff->tstamp = t_start;
			}
			snprintf(tmpstring, 64, "nfcapd.%i%02i%02i%02i%02i.stat", 
				now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min);
			nffd = open(tmpstring, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
			if ( nffd == -1 ) {
				syslog(LOG_ERR, "Can't open stat file: %s", strerror(errno));
				return;
			}

			/* Statfile */
#if defined __OpenBSD__ || defined __FreeBSD__
			snprintf(tmpstring, 64, "Time: %i\n", t_start);
#else
			snprintf(tmpstring, 64, "Time: %li\n", t_start);
#endif
			write(nffd, tmpstring, strlen(tmpstring));
			// t_start = t_now - ( t_now % twin);
			t_start += twin;
			alarm(t_start + twin + OVERDUE_TIME - t_now);

			snprintf(tmpstring, 64, "Ident: %s\n", Ident);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Flows: %llu\n", numflows);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Flows_tcp: %llu\n", numflows_tcp);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Flows_udp: %llu\n", numflows_udp);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Flows_icmp: %llu\n", numflows_icmp);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Flows_other: %llu\n", numflows_other);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Packets: %llu\n", numpackets);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Packets_tcp: %llu\n", numpackets_tcp);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Packets_udp: %llu\n", numpackets_udp);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Packets_icmp: %llu\n", numpackets_icmp);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Packets_other: %llu\n", numpackets_other);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Bytes: %llu\n", numbytes);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Bytes_tcp: %llu\n", numbytes_tcp);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Bytes_udp: %llu\n", numbytes_udp);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Bytes_icmp: %llu\n", numbytes_icmp);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Bytes_other: %llu\n", numbytes_other);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "First: %llu\n", first_seen/1000LL);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Last: %llu\n", last_seen/1000LL);
			write(nffd, tmpstring, strlen(tmpstring));
			close(nffd);
			syslog(LOG_INFO,"Ident: '%s' Flows: %llu, Packets: %llu, Bytes: %llu, Sequence Errors: %u, Bad Packets: %u", 
				Ident, numflows, numpackets, numbytes, sequence_failure, bad_packets);
			if ( launcher_pid ) {
				if ( launcher_alive ) {
					syslog(LOG_DEBUG, "Signal launcher");
					kill(launcher_pid, SIGHUP);
				} else {
					syslog(LOG_ERR, "ERROR: Launcher did unexpectedly!");
				}
			}
			numflows = numbytes = numpackets = 0;
			sequence_failure = bad_packets = 0;
			numflows_tcp = numflows_udp = numflows_icmp = numflows_other = 0;
			numbytes_tcp = numbytes_udp = numbytes_icmp = numbytes_other = 0;
			numpackets_tcp = numpackets_udp = numpackets_icmp = numpackets_other = 0;
			first_seen = 0xffffffffffffLL;
			last_seen = 0;

			nffd = open(NF_DUMPFILE, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
			if ( nffd == -1 ) {
				syslog(LOG_ERR, "Can't open dump file: %s", strerror(errno));
				return;
			}
		}

		/* check for error condition or done */
		if ( cnt < 0 ) {
			if ( rename_trigger ) {	
				rename_trigger = 0;
				continue;
			}
			if ( done ) 
				break;
			else {
				syslog(LOG_ERR, "Data receive error while expecting header data: %s", strerror(errno));
				p = in_buff;
				q = out_buff;
				bad_packets++;
				continue;
			}
		}

		/* Process header */
		nf_header_in  = (netflow_v5_header_t *)p;
		nf_header_out = (flow_header_t *)q;
		
  		nf_header_out->version       = ntohs(nf_header_in->version);
  		nf_header_out->count 		 = ntohs(nf_header_in->count);
  		nf_header_out->SysUptime	 = ntohl(nf_header_in->SysUptime);
  		nf_header_out->unix_secs	 = ntohl(nf_header_in->unix_secs);
  		nf_header_out->unix_nsecs	 = ntohl(nf_header_in->unix_nsecs);
  		nf_header_out->flow_sequence = ntohl(nf_header_in->flow_sequence);
		nf_header_out->layout_version = 1;
		
		// check version and set appropriate params
		switch (nf_header_out->version) {
			case 5: 
				record_length = NETFLOW_V5_RECORD_LENGTH;
				if ( nf_header_out->count == 0 || nf_header_out->count > NETFLOW_V5_MAX_RECORDS ) {
					syslog(LOG_ERR,"Error netflow header: Unexpected number of records in v5 header: %i.", nf_header_out->count);
					buffsize = 0;
					p = in_buff;
					q = out_buff;
					bad_packets++;
					continue;
				}
				break;
			case 7: 
				record_length = NETFLOW_V7_RECORD_LENGTH;
				if ( nf_header_out->count == 0 || nf_header_out->count > NETFLOW_V7_MAX_RECORDS ) {
					syslog(LOG_ERR,"Error netflow header: Unexpected number of records in v7 header: %i.", nf_header_out->count);
					buffsize = 0;
					p = in_buff;
					q = out_buff;
					bad_packets++;
					continue;
				}
				nf_header_out->version = 5;
				break;
			default:
				// force data error, when reading data from socket
				record_length = 0;
				syslog(LOG_ERR,"Error netflow header: Unexpected netflow version %i, found.", nf_header_out->version);
				buffsize = 0;
				p = in_buff;
				q = out_buff;
				bad_packets++;
				continue;
				break;
		}

		if ( first ) {
			last_sequence = nf_header_out->flow_sequence;
			sequence 	  = last_sequence;
			first 		  = 0;
		} else {
			last_sequence = sequence;
			sequence 	  = nf_header_out->flow_sequence;
			distance 	  = sequence - last_sequence;
			// handle overflow
			if (distance < 0) {
				distance = 0xffffffff + distance  +1;
			}
			if (distance != last_count) {
				sequence_failure++;
				if ( report_seq ) 
					syslog(LOG_ERR,"Flow sequence mismatch. Missing: %lli flows", delta(last_count,distance));
			}
		}
		last_count	  = nf_header_out->count;

		if ( verbose ) {
			flow_header_raw(nf_header_out, 0, 0, 0, &string, 0);
			printf("%s", string);
		}

		/* advance buffer */
		p = (void *)((pointer_addr_t)p + header_length);
		q = (void *)((pointer_addr_t)q + header_length);
		buffsize -= header_length;

		/* calculate boot time in msec */
		boot_time  = ((uint64_t)(nf_header_out->unix_secs)*1000 + 
				((uint64_t)(nf_header_out->unix_nsecs) / 1000000) ) - (uint64_t)(nf_header_out->SysUptime);

		/* records associated with the header */
		for (i = 0; i < nf_header_out->count; i++) {
			/* make sure enough data is available in the buffer */
			if ( buffsize > 0 && buffsize < record_length ) {
				syslog(LOG_WARNING, "Data length error: too little data for netflow record!");
				buffsize = 0;
				p = in_buff;
				q = out_buff;
				break;
			}
			if ( buffsize == 0 ) {
				/* read next bunch of data - append to end of data already read */
				cnt = recv (socket, p, (pointer_addr_t)bufflen - ((pointer_addr_t)p  - (pointer_addr_t)in_buff), 0);
				buffsize = cnt;
				if ( cnt < 0 ) {
					if ( done ) {
						break;
					} else {
						syslog(LOG_ERR, "Data receive error while expecting record data: %s", strerror(errno));
						break;
					}
				}
				/* make sure enough data is available in the buffer */
				if ( buffsize > 0 && ((buffsize < record_length) || (record_length == 0)) ) {
					syslog(LOG_WARNING, "Data length error: too little data for v5 record: %i", buffsize);
					buffsize = 0;
					p = in_buff;
					q = out_buff;
					break;
				}
			}
			if ( ( (pointer_addr_t)p - (pointer_addr_t)in_buff ) > bufflen ) {
				/* should never happen, but catch it anyway */
				syslog(LOG_ERR, "Buffer space error");
				buffsize = 0;
				p = in_buff;
				q = out_buff;
				break;
			}
			if ( buffsize < record_length ) {
				syslog(LOG_WARNING, "Data read error: Too little data for v5 record");
				buffsize = 0;
				p = in_buff;
				q = out_buff;
				break;
			}

			// process record
			// whatever netflow version it is ( v5 or v7 allowed here ) both
			// version have the same common fields below
			// fields other than those assigned below or ignored, and not
			// not relevant for nfdump
			v5_record = (netflow_v5_record_t *)p;
			nf_record_out = (flow_record_t *)q;
  			nf_record_out->srcaddr	 = ntohl(v5_record->srcaddr);
  			nf_record_out->dstaddr	 = ntohl(v5_record->dstaddr);
  			nf_record_out->nexthop	 = ntohl(v5_record->nexthop);
  			nf_record_out->input 	 = ntohs(v5_record->input);
  			nf_record_out->output	 = ntohs(v5_record->output);
  			nf_record_out->dPkts 	 = ntohl(v5_record->dPkts);
  			nf_record_out->dOctets	 = ntohl(v5_record->dOctets);
  			First	 				 = ntohl(v5_record->First);
  			Last		 			 = ntohl(v5_record->Last);
  			nf_record_out->srcport	 = ntohs(v5_record->srcport);
  			nf_record_out->dstport	 = ntohs(v5_record->dstport);
  			nf_record_out->pad 		 = 0;
  			nf_record_out->tcp_flags = v5_record->tcp_flags;
  			nf_record_out->prot 	 = v5_record->prot;
  			nf_record_out->tos 		 = v5_record->tos;
  			nf_record_out->src_as	 = ntohs(v5_record->src_as);
  			nf_record_out->dst_as	 = ntohs(v5_record->dst_as);

			switch (nf_record_out->prot) {
				case 1:
					numflows_icmp++;
					numpackets_icmp += nf_record_out->dPkts;
					numbytes_icmp   += nf_record_out->dOctets;
					break;
				case 6:
					numflows_tcp++;
					numpackets_tcp += nf_record_out->dPkts;
					numbytes_tcp   += nf_record_out->dOctets;
					break;
				case 17:
					numflows_udp++;
					numpackets_udp += nf_record_out->dPkts;
					numbytes_udp   += nf_record_out->dOctets;
					break;
				default:
					numflows_other++;
					numpackets_other += nf_record_out->dPkts;
					numbytes_other   += nf_record_out->dOctets;
			}
			numflows++;
			numpackets 	+= nf_record_out->dPkts;
			numbytes	+= nf_record_out->dOctets;

			p = (void *)((pointer_addr_t)p + record_length);
			q = (void *)((pointer_addr_t)q + NETFLOW_V5_RECORD_LENGTH);
			buffsize -= record_length;

			/* start time in msecs */
			start_time = (uint64_t)First + boot_time;

			if ( First > Last )
				/* Last in msec, in case of msec overflow, between start and end */
				end_time = 0x100000000LL + Last + boot_time;
			else
				end_time = (uint64_t)Last + boot_time;

			nf_record_out->First 		= start_time/1000;
			nf_record_out->msec_first	= start_time - nf_record_out->First*1000;

			nf_record_out->Last 		= end_time/1000;
			nf_record_out->msec_last	= end_time - nf_record_out->Last*1000;

			if ( start_time < first_seen )
				first_seen = start_time;
			if ( end_time > last_seen )
				last_seen = end_time;

			if ( verbose ) {
				flow_record_raw(nf_record_out, 1, (uint64_t)nf_record_out->dPkts, (uint64_t)nf_record_out->dOctets, &string, 0);
				printf("%s\n", string);
			}
		}
		if ( i != nf_header_out->count ) {
			syslog(LOG_WARNING, "Expected %i records, but found only %i", nf_header_out->count, i);
			nf_header_out->count = i;
		}
		writesize = header_length + nf_header_out->count * NETFLOW_V5_RECORD_LENGTH;
		if ( write(nffd, (void *)nf_header_out, writesize) <= 0 ) {
			syslog(LOG_ERR, "Failed to write records to disk: '%s'" , strerror(errno));
		}
	}
	free(in_buff);
	free(out_buff);
	close(nffd);

} /* End of run */

int main(int argc, char **argv) {
 
char	*bindaddr, *pidfile, *filter, *datadir, pidstr[32], *lauch_process;
char	*userid, *groupid, *checkptr;
struct stat fstat;
srecord_t	*commbuff;
struct sigaction act;
int		bufflen;
time_t 	twin, t_start, t_tmp;
int		portnum, sock, pidf, fd, err, synctime, daemonize, report_sequence;
char	c;
pid_t	pid;

	portnum  		= verbose = synctime = daemonize = 0;
	bufflen  		= 0;
	launcher_pid	= 0;
	launcher_alive	= 0;
	report_sequence	= 0;
	bindaddr 		= NULL;
	pidfile  		= NULL;
	filter   		= NULL;
	lauch_process	= NULL;
	userid 			= groupid = NULL;
	twin	 		= TIME_WINDOW;
	datadir	 		= DEFAULT_DIR;
	strncpy(Ident, "none", IDENT_SIZE);
	while ((c = getopt(argc, argv, "whEVI:DB:b:l:p:P:t:x:ru:g:")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
				break;
			case 'u':
				userid  = optarg;
				break;
			case 'g':
				groupid  = optarg;
				break;
			case 'E':
				verbose = 1;
				break;
			case 'V':
				printf("%s: Version: %s %s\n%s\n",argv[0], nfdump_version, nfdump_date, rcsid);
				exit(0);
				break;
			case 'D':
				daemonize = 1;
				break;
			case 'I':
				strncpy(Ident, optarg, IDENT_SIZE);
				Ident[IDENT_SIZE - 1] = 0;
				if ( strchr(Ident, ' ') ) {
					fprintf(stderr,"Ident must not contain spaces\n");
					exit(255);
				}
				break;
			case 'w':
				synctime = 1;
				break;
			case 'B':
				bufflen = strtol(optarg, &checkptr, 10);
				if ( (checkptr != NULL && *checkptr == 0) && bufflen > 0 )
					break;
				fprintf(stderr,"Argument error for -B\n");
				exit(255);
			case 'b':
				bindaddr = optarg;
				break;
			case 'p':
				portnum = strtol(optarg, &checkptr, 10);
				if ( (checkptr != NULL && *checkptr == 0) && portnum > 0 )
					break;
				fprintf(stderr,"Argument error for -p\n");
				exit(255);
				break;
			case 'P':
				pidfile = optarg;
				break;
			case 'r':
				report_sequence = 1;
				break;
			case 'l':
				datadir = optarg;
				err  = stat(datadir, &fstat);
				if ( !(fstat.st_mode & S_IFDIR) ) {
					fprintf(stderr, "No such directory: %s\n", datadir);
					break;
				}
				break;
			case 't':
				twin = atoi(optarg);
				if ( twin <= 0 ) {
					fprintf(stderr, "ERROR: time frame <= 0\n");
					exit(255);
				}
				if (twin < 60) {
					fprintf(stderr, "WARNING, Very small time frame - < 60s!\n");
				}
				break;
			case 'x':
				lauch_process = optarg;
				break;
			default:
				usage(argv[0]);
				exit(255);
		}
	}

	openlog(argv[0] , LOG_CONS|LOG_PID, SYSLOG_FACILITY);

	SetPriv(userid, groupid);

	if ( pidfile ) {
		pidf = open(pidfile, O_CREAT|O_RDWR, 0644);
		if ( pidf == -1 ) {
			syslog(LOG_ERR, "Error opening pid file '%s': %s", pidfile, strerror(errno));
			fprintf(stderr,"Terminated due to errors.\n");
			exit(255);
		}
		pid = getpid();
		snprintf(pidstr,31,"%i\n", pid);
		write(pidf, pidstr, strlen(pidstr));
		close(pidf);
	}

	if ( lauch_process ) {
		// for efficiency reason, the process collecting the data
		// and the process launching processes, when a new file becomes
		// available are separated. Communication is done using signals
		// as well as shared memory
		// prepare shared memory
		shmem = mmap(0, sizeof(srecord_t), PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
		if ( shmem == (caddr_t)-1 ) {
	  		perror("mmap error");
			exit(255);
		}

		commbuff = (srecord_t *)shmem;
		strncpy(commbuff->ident, Ident, IDENT_SIZE );
		commbuff->ident[IDENT_SIZE - 1] = 0;

		if ((launcher_pid = fork()) == -1) {
			syslog(LOG_ERR, "Can't fork: %s", strerror(errno));
	  		perror("Can't fork()");
		} else if ( launcher_pid == 0 ) { // child

			// close stdin, stdout and stderr
			close(0);
			close(1);
			close(2);
			fd = open("/dev/null",O_RDWR); /* open stdin */
			dup(fd); /* stdout */
			dup(fd); /* stdout */

			launcher((char *)shmem, datadir, lauch_process);
			exit(0);
		} else {
			launcher_alive = 1;
			syslog(LOG_DEBUG, "Launcher forked");
		}
		// parent continues 
	}

	if (argc - optind > 1) {
		usage(argv[0]);
		kill_launcher(launcher_pid);
		exit(255);
	} else {
		/* user specified a pcap filter */
		filter = argv[optind];
	}

	sock = Setup_Socket(bindaddr, portnum, bufflen );
	if ( sock == -1 ) {
		kill_launcher(launcher_pid);
		fprintf(stderr,"Terminated due to errors.\n");
		exit(255);
	}

	if ( synctime ) {
		t_tmp = time(NULL);
		t_start = t_tmp - ( t_tmp % twin);
	} else
		t_start = time(NULL);

	if ( daemonize ) {
		verbose = 0;
		if ((pid = fork()) < 0 ) {
	  		perror("Can't fork()");
		} else if (pid) {
	  		if (pidfile) {
				pidf = open(pidfile, O_CREAT|O_RDWR, 0644);
				if ( pidf == -1 ) {
					syslog(LOG_ERR, "Error opening pid file: '%s' %s", pidfile, strerror(errno));
					perror("Error opening pid file:");
					kill_launcher(launcher_pid);
					exit(255);
				}
				snprintf(pidstr,31,"%i\n", pid);
				write(pidf, pidstr, strlen(pidstr));
				close(pidf);
			}
	  		exit (0); /* parent */
		} // else -> child continues

		if (setsid() < 0) {
			syslog(LOG_ERR, "Can't create new session: '%s'", strerror(errno));
			exit(255);
		}
		// close stdin, stdout and stderr
		close(0);
		close(1);
		close(2);
		fd = open("/dev/null",O_RDWR); /* open stdin */
		dup(fd); /* stdout */
		dup(fd); /* stdout */
	}

	if ( chdir(datadir)) {
		syslog(LOG_ERR, "Error can't chdir to '%s': %s", datadir, strerror(errno));
		kill_launcher(launcher_pid);
		exit(255);
	}
	done = 0;

	/* Signal handling */
	memset((void *)&act,0,sizeof(struct sigaction));
	act.sa_handler = IntHandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);

	syslog(LOG_INFO, "Startup.");
	run(sock, bufflen, twin, t_start, report_sequence);
	close(sock);
	syslog(LOG_INFO, "Terminating nfcapd.");

	if ( pidfile ) 
		unlink(pidfile);

	closelog();
	kill_launcher(launcher_pid);
	exit(0);

} /* End of main */
