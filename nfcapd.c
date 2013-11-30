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
 *  $Id: nfcapd.c 15 2004-12-20 12:43:36Z peter $
 *
 *  $LastChangedRevision: 15 $
 *	
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
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


#define SYSLOG_FACILITY LOG_DAEMON

/* Global Variables */
uint32_t	byte_limit, packet_limit;	// needed for linking purpose only
int 		byte_mode, packet_mode;
caddr_t		shmem;

/*
 * local static vars used by interrupt routine
 */
static int done, rename_trigger, launcher_pid, verbose = 0;
static char Ident[32];

static char const *rcsid 		  = "$Id: nfcapd.c 15 2004-12-20 12:43:36Z peter $";

/* Function Prototypes */
static void IntHandler(int signal);

static void usage(char *name);

static SetPriv(char *userid, char *groupid );

static int Setup_Socket(char *IPAddr, int portnum, long sockbuflen );

static void kill_launcher(int pid);

void kill_launcher(int pid) {
int stat;

	if ( pid == 0 )
		return;

	kill(pid, SIGTERM);
	waitpid (pid, &stat, WNOHANG);

} // End of kill_launcher


static void run(int socket, unsigned int bufflen, time_t twin, time_t t_begin);

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
			if ( !done ) 
				syslog(LOG_ERR, "SIGCHLD laucher died!\n");
			else
				syslog(LOG_ERR, "laucher terminated\n");
			break;
		default:
			syslog(LOG_ERR, "Unknown signal '%i' received\n", signal);
	}

} /* End of IntHandler */

static SetPriv(char *userid, char *groupid ) {
struct 	passwd *pw_entry;
struct 	group *gr_entry;
uid_t	myuid, newuid, newgid;
int		err;

	if ( userid == 0 && groupid == 0 )
		return;

	newuid = newgid = 0;
	myuid = getuid();
	if ( myuid != 0 ) {
		syslog(LOG_ERR, "Only root wants to change uid/gid\n");
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
			syslog(LOG_ERR, "Can't set group id %i for group '%s': %s\n", newgid, groupid, strerror(errno));
			fprintf (stderr,"Can't set group id %i for group '%s': %s\n", newgid, groupid, strerror(errno));
			exit(255);
		}

	}

	if ( newuid ) {
		err = setuid(newuid);
		if ( err ) {
			syslog(LOG_ERR, "Can't set user id %i for user '%s': %s\n", newuid, userid, strerror(errno));
			fprintf (stderr,"Can't set user id %i for user '%s': %s\n", newuid, userid, strerror(errno));
			exit(255);
		}
	}

} // End of SetPriv

static int Setup_Socket(char *IPAddr, int portnum, long sockbuflen ) {
struct sockaddr_in server;
int s, p;
socklen_t	   optlen;


	if ( !portnum ) 
		portnum = DEFAULTCISCOPORT;

	s = socket (AF_INET, SOCK_DGRAM, 0);
	if ( s < 0 ) {
		fprintf(stderr, "Can't open socket: %s\n", strerror(errno));
		syslog(LOG_ERR, "Can't open socket: %s\n", strerror(errno));
		return -1;
	}

	memset ((char *) &server, 0, sizeof (server));

	server.sin_addr.s_addr = IPAddr ? inet_addr(IPAddr) : INADDR_ANY;
	server.sin_family = AF_INET;
	server.sin_port = htons(portnum);

	if ( (bind (s, (struct sockaddr *)&server, sizeof(server))) < 0 ) {
		fprintf(stderr, "bind to %s:%i failed: %s\n", inet_ntoa(server.sin_addr), portnum, strerror(errno));
		syslog(LOG_WARNING, "bind to %s:%i failed: %s\n", inet_ntoa(server.sin_addr), portnum, strerror(errno));
		close(s);
		return -1;
	}

	if ( sockbuflen ) {
		getsockopt(s,SOL_SOCKET,SO_RCVBUF,&p,&optlen);
		syslog(LOG_INFO,"Standard setsockopt, SO_RCVBUF is %i Requested length is %li bytes\n",p, sockbuflen);
		if ((setsockopt(s, SOL_SOCKET, SO_RCVBUF, &sockbuflen, sizeof(sockbuflen)) != 0) ) {
			fprintf (stderr, "setsockopt(SO_RCVBUF,%ld): %s\n", sockbuflen, strerror (errno));
			syslog (LOG_WARNING, "setsockopt(SO_RCVBUF,%ld): %s\n", sockbuflen, strerror (errno));
			close(s);
			return -1;
		} else {
			getsockopt(s,SOL_SOCKET,SO_RCVBUF,&p,&optlen);
			syslog(LOG_INFO,"Set setsockopt, SO_RCVBUF to %d bytes\n", p);
		}
	} 

	return s;

}  /* End of Setup_Socket */


static void run(int socket, unsigned int bufflen, time_t twin, time_t t_begin) {
size_t writesize;
ssize_t	cnt;
nf_header_t *nf_header_in, *nf_header_out;			// v5/v7 common header
netflow_v5_record_t *v5_record, *nf_record_out;
time_t 		t_start, t_now;
uint32_t	buffsize;
uint64_t	numflows, numbytes, numpackets;
uint64_t	numflows_tcp, numflows_udp, numflows_icmp, numflows_other;
uint64_t	numbytes_tcp, numbytes_udp, numbytes_icmp, numbytes_other;
uint64_t	numpackets_tcp, numpackets_udp, numpackets_icmp, numpackets_other;
uint32_t	start_time, end_time, first_seen, last_seen;
struct  tm *now;
void 		*in_buff, *out_buff, *p, *q;
int 		i, err, nffd, header_length, record_length;
char 		*string, tmpstring[64];
srecord_t	*commbuff;
double		boot_time;

	if ( !bufflen || bufflen < BUFFSIZE ) 
		bufflen = BUFFSIZE;

	in_buff  = malloc(bufflen);
	out_buff = malloc(bufflen);
	if ( !in_buff || !out_buff ) {
		syslog(LOG_ERR, "Buffer allocation error: %s\n", strerror(errno));
		return;
	}

	// init vars
	commbuff = (srecord_t *)shmem;

	p = in_buff;
	q = out_buff;
	cnt = 0;
	nf_header_in  = nf_header_out = NULL;
	v5_record     = nf_record_out = NULL;
	header_length = NETFLOW_V5_HEADER_LENGTH;	// v5 and v7 have same length

	nffd = open(NF_DUMPFILE, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
	if ( nffd == -1 ) {
		syslog(LOG_ERR, "Can't open file: %s\n", strerror(errno));
		return;
	}

	first_seen = 0xffffffff;
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
			syslog(LOG_WARNING, "Data length error: too little data for netflow v5 header: %i\n", buffsize);
			buffsize = 0;
			p = in_buff;
			q = out_buff;
			break;
		}
		/* read next bunch of data into beginn of input buffer */
		if ( buffsize == 0 ) {
			cnt = recv (socket, in_buff, bufflen , 0);
			buffsize = cnt > 0 ? cnt : 0;
			p = in_buff;
			q = out_buff;
			/* check for too little data */
			if ( buffsize > 0 && buffsize < header_length ) {
				syslog(LOG_WARNING, "Data length error: too little data for netflow header: %i\n", buffsize);
				buffsize = 0;
				p = in_buff;
				q = out_buff;
				break;
			}
		}
		/* paranoia check */
		if ( ( (pointer_addr_t)p - (pointer_addr_t)in_buff ) > bufflen ) {
			/* should never happen, but catch it anyway */
			syslog(LOG_ERR, "Buffer space error");
			buffsize = 0;
			p = in_buff;
			q = out_buff;
			break;
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
				syslog(LOG_ERR, "Can't rename dump file: %s\n", strerror(errno));
				break;
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
				syslog(LOG_ERR, "Can't open stat file: %s\n", strerror(errno));
				return;
			}

			/* Statfile */
			snprintf(tmpstring, 64, "Time: %li\n", t_start);
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
			snprintf(tmpstring, 64, "First: %u\n", first_seen);
			write(nffd, tmpstring, strlen(tmpstring));
			snprintf(tmpstring, 64, "Last: %u\n", last_seen);
			write(nffd, tmpstring, strlen(tmpstring));
			close(nffd);
			if ( launcher_pid ) {
				// printf("Signal launcher\n");
				kill(launcher_pid, SIGHUP);
			}
			numflows = numbytes = numpackets = 0;
			numflows_tcp = numflows_udp = numflows_icmp = numflows_other = 0;
			numbytes_tcp = numbytes_udp = numbytes_icmp = numbytes_other = 0;
			numpackets_tcp = numpackets_udp = numpackets_icmp = numpackets_other = 0;
			first_seen = 0xffffffff;
			last_seen = 0;

			nffd = open(NF_DUMPFILE, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
			if ( nffd == -1 ) {
				syslog(LOG_ERR, "Can't open dump file: %s\n", strerror(errno));
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
				syslog(LOG_ERR, "Data receive error while expecting header data: %s\n", strerror(errno));
				break;
			}
		}

		/* Process header */
		nf_header_in  = (nf_header_t *)p;
		nf_header_out = (nf_header_t *)q;
		
  		nf_header_out->version       = ntohs(nf_header_in->version);
  		nf_header_out->count 		 = ntohs(nf_header_in->count);
  		nf_header_out->SysUptime	 = ntohl(nf_header_in->SysUptime);
  		nf_header_out->unix_secs	 = ntohl(nf_header_in->unix_secs);
  		nf_header_out->unix_nsecs	 = ntohl(nf_header_in->unix_nsecs);
  		nf_header_out->flow_sequence = ntohl(nf_header_in->flow_sequence);
		
		// check version and set appropriate params
		switch (nf_header_out->version) {
			case 5: 
				record_length = NETFLOW_V5_RECORD_LENGTH;
				break;
			case 7: 
				record_length = NETFLOW_V7_RECORD_LENGTH;
				nf_header_out->version = 5;
				break;
			default:
				// force data error, when reading data from socket
				record_length = 0;
				syslog(LOG_ERR,"Error netflow header: Unexpected netflow version %i, found.\n", nf_header_out->version);
				buffsize = 0;
				p = in_buff;
				q = out_buff;
				break;
		}

		if ( verbose ) {
			netflow_v5_header_to_string(nf_header_out, &string);
			printf("%s", string);
		}

		/* advance buffer */
		p = (void *)((pointer_addr_t)p + header_length);
		q = (void *)((pointer_addr_t)q + header_length);
		buffsize -= header_length;

		/* records associated with the header */
		for (i = 0; i < nf_header_out->count; i++) {
			/* make sure enough data is available in the buffer */
			if ( buffsize > 0 && buffsize < record_length ) {
				syslog(LOG_WARNING, "Data length error: too little data for netflow record!\n");
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
						syslog(LOG_ERR, "Data receive error while expecting record data: %s\n", strerror(errno));
						break;
					}
				}
				/* make sure enough data is available in the buffer */
				if ( buffsize > 0 && ((buffsize < record_length) || (record_length == 0)) ) {
					syslog(LOG_WARNING, "Data length error: too little data for v5 record: %i\n", buffsize);
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
				syslog(LOG_WARNING, "Data read error: Too little data for v5 record\n");
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
			nf_record_out = (netflow_v5_record_t *)q;
  			nf_record_out->srcaddr	 = ntohl(v5_record->srcaddr);
  			nf_record_out->dstaddr	 = ntohl(v5_record->dstaddr);
  			nf_record_out->nexthop	 = ntohl(v5_record->nexthop);
  			nf_record_out->input 	 = ntohs(v5_record->input);
  			nf_record_out->output	 = ntohs(v5_record->output);
  			nf_record_out->dPkts 	 = ntohl(v5_record->dPkts);
  			nf_record_out->dOctets	 = ntohl(v5_record->dOctets);
  			nf_record_out->First	 = ntohl(v5_record->First);
  			nf_record_out->Last		 = ntohl(v5_record->Last);
  			nf_record_out->srcport	 = ntohs(v5_record->srcport);
  			nf_record_out->dstport	 = ntohs(v5_record->dstport);
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

			/* patch the First and Last time stamps in the netflow record to UNIX timestamps
			 * This will be reverted when resending the netflow data, with the costs of loosing 
			 * msec units
			 */
			boot_time  = ((double)(nf_header_out->unix_secs) + 1e-9 * (double)(nf_header_out->unix_nsecs)) - 
				(0.001 * (double)(nf_header_out->SysUptime));
			start_time = (uint32_t)(nf_record_out->First)/1000 + boot_time;
			end_time   = (uint32_t)(nf_record_out->Last)/1000 + boot_time;
			nf_record_out->First = start_time;
			nf_record_out->Last  = end_time;
			if ( start_time < first_seen )
				first_seen = start_time;
			if ( end_time > last_seen )
				last_seen = end_time;

			if ( verbose ) {
				netflow_v5_record_to_block(nf_record_out, &string);
				printf("%s\n", string);
			}
		}
		if ( i != nf_header_out->count ) {
			syslog(LOG_WARNING, "Expected %i records, but found only %i\n", nf_header_out->count, i);
			nf_header_out->count = i;
		}
		writesize = header_length + nf_header_out->count * NETFLOW_V5_RECORD_LENGTH;
		write(nffd, (void *)nf_header_out, writesize);
	}
	free(in_buff);
	free(out_buff);
	close(nffd);

} /* End of run */

int main(int argc, char **argv) {
 
char	*bindaddr, *pidfile, *filter, *datadir, pidstr[32], *lauch_process;
char	*userid, *groupid;
struct stat fstat;
srecord_t	*commbuff;
struct sigaction act;
unsigned long	bufflen;
time_t 	twin, t_start, t_tmp;
int		portnum, sock, pidf, err, synctime, daemonize;
char	c;
pid_t	pid;

	portnum  		= verbose = synctime = daemonize = 0;
	bufflen  		= 0;
	launcher_pid	= 0;
	bindaddr 		= NULL;
	pidfile  		= NULL;
	filter   		= NULL;
	lauch_process	= NULL;
	userid 			= groupid = NULL;
	twin	 		= TIME_WINDOW;
	datadir	 		= DEFAULT_DIR;
	strncpy(Ident, "none", IDENT_SIZE);
	while ((c = getopt(argc, argv, "whEVI:DB:b:l:p:P:t:x:u:g:")) != EOF) {
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
				bufflen = atoi(optarg);
				break;
			case 'b':
				bindaddr = optarg;
				break;
			case 'p':
				portnum = atoi(optarg);
				break;
			case 'P':
				pidfile = optarg;
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
				if (twin < 60) {
					fprintf(stderr, "WARNING, very small time frame - < 60s!\n");
				}
				if ( twin <= 0 ) {
					fprintf(stderr, "ERROR: time frame <= 0\n");
					exit(255);
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
			syslog(LOG_ERR, "Error opening pid file: %s\n", strerror(errno));
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
			syslog(LOG_ERR, "Can't fork: %s\n", strerror(errno));
	  		perror("Can't fork()");
		} else if ( launcher_pid == 0 ) { // child
			launcher((char *)shmem, datadir, lauch_process);
			exit(0);
		} // parent continues
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
		if ((pid = fork()) == -1) {
	  		perror("Can't fork()");
		} else if (pid) {
	  		if (pidfile) {
				pidf = open(pidfile, O_CREAT|O_RDWR, 0644);
				if ( pidf == -1 ) {
					syslog(LOG_ERR, "Error opening pid file: %s\n", strerror(errno));
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
	}

	if ( chdir(datadir)) {
		syslog(LOG_ERR, "Error can't chdir: %s\n", strerror(errno));
		kill_launcher(launcher_pid);
		fprintf(stderr,"Terminated due to errors.\n");
		exit(255);
	}
	done = 0;

	/* Signal handling */
	act.sa_handler = IntHandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGALRM, &act, NULL);
	sigaction(SIGCHLD, &act, NULL);

	syslog(LOG_INFO, "Startup.\n");
	run(sock, bufflen, twin, t_start);
	close(sock);
	syslog(LOG_INFO, "Terminating nfcapd.\n");

	if ( pidfile ) 
		unlink(pidfile);

	closelog();
	kill_launcher(launcher_pid);
	exit(0);

} /* End of main */
