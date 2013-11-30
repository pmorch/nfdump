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
 *  $Id: nfcapd.c 2 2004-09-20 18:12:36Z peter $
 *
 *  $LastChangedRevision: 2 $
 *	
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>

#include "config.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "version.h"
#include "nf_common.h"
#include "netflow_v5.h"
#include "netflow_v7.h"

#define DEFAULTCISCOPORT 9995
#define TIME_WINDOW	  300 
#define DEFAULT_DIR	  "/var/tmp"

#define BUFFSIZE 655350
#define NF_DUMPFILE "nfcapd.current"

#define SYSLOG_FACILITY LOG_DAEMON

/* Global Variables */
uint32_t	byte_limit, packet_limit;	// needed for linking purpose only
int 		byte_mode, packet_mode;

/*
 * local static vars used by interrupt routine
 */
static int done, verbose = 0;
static int shut_v5_slow_path = 0;
static char Ident[32];
static int netflow_version;

static char const *rcsid 		  = "$Id: nfcapd.c 2 2004-09-20 18:12:36Z peter $";

/* Function Prototypes */
static void IntHandler(int signal);

static void usage(char *name);

static int Setup_Socket(char *IPAddr, int portnum, long sockbuflen );

static void run(int socket, unsigned int bufflen, time_t twin, time_t t_begin);

/* Functions */
static void usage(char *name) {
		printf("usage %s [options] \n"
					"-h\t\tthis text you see right here\n"
					"-w\t\tSync file rotation with next 5min (default) interval\n"
					"-t interval\tset the interval to rotate nfcapd files\n"
					"-b ipaddr\tbind socket to IP addr\n"
					"-p portnum\tlisten on port portnum\n"
					"-l log directory\tset the output directory. (default /var/tmp) \n"
					"-I <Ident string>\tset the ident string for stat file. (default 'none')\n"
					"-P pidfile\tset the PID file\n"
					"-v version\tset netflow version (default 5)\n"
					"-B bufflen\tSet socket buffer to bufflen bytes\n"
					"-D\t\tFork to background\n"
					"-Q\t\tDo not complain for CISCO v5 Slow-Path traffic in v7 mode.\n"
					"-E\t\tPrint extended format of netflow data. for debugging purpose only.\n"
					"-V\t\tPrint version and exit.\n"
					, name);
} /* usage */

static void IntHandler(int signal) {
		done = 1;
} /* End of IntHandler */

static int Setup_Socket(char *IPAddr, int portnum, long sockbuflen ) {
struct sockaddr_in server;
int s, p;
socklen_t	   optlen;


	if ( !portnum ) 
		portnum = DEFAULTCISCOPORT;

	s = socket (AF_INET, SOCK_DGRAM, 0);
	if ( s < 0 ) {
		perror("Can't open socket:");
		return -1;
	}

	memset ((char *) &server, 0, sizeof (server));

	server.sin_addr.s_addr = IPAddr ? inet_addr(IPAddr) : INADDR_ANY;
	server.sin_family = AF_INET;
	server.sin_port = htons(portnum);

	if ( (bind (s, (struct sockaddr *)&server, sizeof(server))) < 0 ) {
		syslog(LOG_WARNING, "bind to %s:%i failed: %s\n", inet_ntoa(server.sin_addr), portnum, strerror(errno));
		close(s);
		return -1;
	}

	if ( sockbuflen ) {
		getsockopt(s,SOL_SOCKET,SO_RCVBUF,&p,&optlen);
		syslog(LOG_INFO,"Standard setsockopt, SO_RCVBUF is %i Requested length is %li bytes\n",p, sockbuflen);
		if ((setsockopt(s, SOL_SOCKET, SO_RCVBUF, &sockbuflen, sizeof(sockbuflen)) != 0) ) {
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
nf_header_t *nf_header;			// v5/v7 common header
netflow_v7_record_t *nf_record;	// v7 record also includes v5 structure
time_t t_start, t_now, t_tmp;
uint32_t	buffsize;
uint64_t	numflows, numbytes, numpackets;
uint64_t	numflows_tcp, numflows_udp, numflows_icmp, numflows_other;
uint64_t	numbytes_tcp, numbytes_udp, numbytes_icmp, numbytes_other;
uint64_t	numpackets_tcp, numpackets_udp, numpackets_icmp, numpackets_other;
uint32_t	start_time, end_time, first_seen, last_seen;
struct  tm *now;
void *buff, *p;
int i, err, nffd, header_length, record_length;
char *string, tmpstring[64];
double		boot_time;
printer_t	print_header, print_record;

	if ( !bufflen || bufflen < BUFFSIZE ) 
		bufflen = BUFFSIZE;

	buff = malloc(bufflen);
	if ( !buff ) {
		perror("Buffer allocation error");
		return;
	}
	p = buff;
	cnt = 0;
	nf_header = NULL;

	switch (netflow_version) {
		case 5: 
				header_length = NETFLOW_V5_HEADER_LENGTH;
				record_length = NETFLOW_V5_RECORD_LENGTH;
				print_header  = netflow_v5_header_to_string;
				print_record  = netflow_v5_record_to_string;
			break;
		case 7: 
				header_length = NETFLOW_V7_HEADER_LENGTH;
				record_length = NETFLOW_V7_RECORD_LENGTH;
				print_header  = netflow_v7_header_to_string;
				print_record  = netflow_v7_record_to_string;
			break;

		default:
			// this should never occure as the netflow version was checked
			syslog(LOG_WARNING, "Netflow version error\n");
			return;
	}

	nffd = open(NF_DUMPFILE, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
	if ( nffd == -1 ) {
		perror("Can't open file: ");
		return;
	}

	first_seen = 0xffffffff;
	last_seen = 0;
	t_start = t_begin;
	numflows = numbytes = numpackets = buffsize = 0;
	numflows_tcp = numflows_udp = numflows_icmp = numflows_other = 0;
	numbytes_tcp = numbytes_udp = numbytes_icmp = numbytes_other = 0;
	numpackets_tcp = numpackets_udp = numpackets_icmp = numpackets_other = 0;
	while ( !done ) {
		/* check for too little data */
		if ( buffsize > 0 && buffsize < header_length ) {
			syslog(LOG_WARNING, "Data length error: too little data for netflow v5 header: %i\n", buffsize);
			buffsize = 0;
			p = buff;
			break;
		}
		/* read next bunch of data into beginn of buffer */
		if ( buffsize == 0 ) {
			cnt = recv (socket, buff, bufflen , 0);
			buffsize = cnt;
			p = buff;
			/* check for too little data */
			if ( buffsize > 0 && buffsize < header_length ) {
				syslog(LOG_WARNING, "Data length error: too little data for netflow v5 header: %i\n", buffsize);
				buffsize = 0;
				p = buff;
				break;
			}
		}
		/* paranoia check */
		if ( ( (pointer_addr_t)p - (pointer_addr_t)buff ) > bufflen ) {
			/* should never happen, but catch it anyway */
			syslog(LOG_ERR, "Buffer space error");
			buffsize = 0;
			p = buff;
			break;
		}

		/* File renaming */
		t_now = time(NULL);
		if ( ((t_now - t_start) >= twin) || done ) {
			t_tmp = time(NULL);
			now = localtime(&t_start);
			snprintf(tmpstring, 64, "nfcapd.%i%02i%02i%02i%02i", 
				now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min);
			close(nffd);
			err = rename(NF_DUMPFILE, tmpstring);
			if ( err ) {
				perror("Can't rename dump file:");
				break;
			}

			snprintf(tmpstring, 64, "nfcapd.%i%02i%02i%02i%02i.stat", 
				now->tm_year + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min);
			nffd = open(tmpstring, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
			if ( nffd == -1 ) {
				perror("Can't open stat file: ");
				return;
			}

			/* Statfile */
			snprintf(tmpstring, 64, "Time: %li\n", t_start);
			write(nffd, tmpstring, strlen(tmpstring));
			t_start = t_tmp - ( t_tmp % twin);

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
			numflows = numbytes = numpackets = 0;
			numflows_tcp = numflows_udp = numflows_icmp = numflows_other = 0;
			numbytes_tcp = numbytes_udp = numbytes_icmp = numbytes_other = 0;
			numpackets_tcp = numpackets_udp = numpackets_icmp = numpackets_other = 0;
			first_seen = 0xffffffff;
			last_seen = 0;

			nffd = open(NF_DUMPFILE, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH );
			if ( nffd == -1 ) {
				perror("Can't open dump file: ");
				return;
			}
		}

		/* check for error condition or done */
		if ( cnt < 0 ) {
			if ( done ) 
				break;
			else {
				perror("Data receive error");
				break;
			}
		}

		/* Process header */
		nf_header= (nf_header_t *)p;
  		nf_header->version = ntohs(nf_header->version);
  		if ((nf_header->version != netflow_version) ) {
			if ( shut_v5_slow_path == 0 ) {
				syslog(LOG_WARNING,"Error netflow header: Expected version %i, found %i\n", netflow_version, nf_header->version);

				/* For Debugging purpose
  				nf_header->count 		 = ntohs(nf_header->count);
  				nf_header->SysUptime	 = ntohl(nf_header->SysUptime);
  				nf_header->unix_secs	 = ntohl(nf_header->unix_secs);
  				nf_header->unix_nsecs	 = ntohl(nf_header->unix_nsecs);
  				nf_header->flow_sequence = ntohl(nf_header->flow_sequence);
				print_header(nf_header, &string);
				printf("%s", string);
				// End Debugging 
				*/
			}

			buffsize = 0;
			continue;
  		}
  		nf_header->count 		 = ntohs(nf_header->count);
  		nf_header->SysUptime	 = ntohl(nf_header->SysUptime);
  		nf_header->unix_secs	 = ntohl(nf_header->unix_secs);
  		nf_header->unix_nsecs	 = ntohl(nf_header->unix_nsecs);
  		nf_header->flow_sequence = ntohl(nf_header->flow_sequence);

		if ( verbose ) {
			print_header(nf_header, &string);
			printf("%s", string);
		}

		/* advance buffer */
		p = (void *)((pointer_addr_t)p + header_length);
		buffsize -= header_length;

		/* records associated with the header */
		for (i = 0; i < nf_header->count; i++) {
			/* make sure enough data is available in the buffer */
			if ( buffsize > 0 && buffsize < record_length ) {
				syslog(LOG_WARNING, "Data length error: too little data for v%i record: %i \n", netflow_version, buffsize);
				buffsize = 0;
				p = buff;
				break;
			}
			if ( buffsize == 0 ) {
				/* read next bunch of data - append to end of data already read */
				cnt = recv (socket, p, (pointer_addr_t)bufflen - ((pointer_addr_t)p  - (pointer_addr_t)buff), 0);
				buffsize = cnt;
				if ( cnt < 0 ) {
					if ( done ) {
						break;
					} else {
						perror("Data receive error");
						break;
					}
				}
				/* make sure enough data is available in the buffer */
				if ( buffsize > 0 && buffsize < record_length ) {
					syslog(LOG_WARNING, "Data length error: too little data for v5 record: %i\n", buffsize);
					buffsize = 0;
					p = buff;
					break;
				}
			}
			if ( ( (pointer_addr_t)p - (pointer_addr_t)buff ) > bufflen ) {
				/* should never happen, but catch it anyway */
				syslog(LOG_ERR, "Buffer space error");
				buffsize = 0;
				p = buff;
				break;
			}
			if ( buffsize < record_length ) {
				syslog(LOG_WARNING, "Data read error: Too little data for v5 record\n");
				buffsize = 0;
				p = buff;
				break;
			}

			// process record
			nf_record = (netflow_v7_record_t *)p;

  			nf_record->srcaddr	= ntohl(nf_record->srcaddr);
  			nf_record->dstaddr	= ntohl(nf_record->dstaddr);
  			nf_record->nexthop	= ntohl(nf_record->nexthop);
  			nf_record->input 	= ntohs(nf_record->input);
  			nf_record->output	= ntohs(nf_record->output);
  			nf_record->dPkts 	= ntohl(nf_record->dPkts);
  			nf_record->dOctets	= ntohl(nf_record->dOctets);
  			nf_record->First	= ntohl(nf_record->First);
  			nf_record->Last		= ntohl(nf_record->Last);
  			nf_record->srcport	= ntohs(nf_record->srcport);
  			nf_record->dstport	= ntohs(nf_record->dstport);
  			nf_record->src_as	= ntohs(nf_record->src_as);
  			nf_record->dst_as	= ntohs(nf_record->dst_as);
  			nf_record->pad		= ntohs(nf_record->pad);
			if ( netflow_version == 7 )
  				nf_record->router_sc	= ntohl(nf_record->router_sc);

			switch (nf_record->prot) {
				case 1:
					numflows_icmp++;
					numpackets_icmp += nf_record->dPkts;
					numbytes_icmp   += nf_record->dOctets;
					break;
				case 6:
					numflows_tcp++;
					numpackets_tcp += nf_record->dPkts;
					numbytes_tcp   += nf_record->dOctets;
					break;
				case 17:
					numflows_udp++;
					numpackets_udp += nf_record->dPkts;
					numbytes_udp   += nf_record->dOctets;
					break;
				default:
					numflows_other++;
					numpackets_other += nf_record->dPkts;
					numbytes_other   += nf_record->dOctets;
			}
			numflows++;
			numpackets 	+= nf_record->dPkts;
			numbytes	+= nf_record->dOctets;

			p = (void *)((pointer_addr_t)p + record_length);
			buffsize -= record_length;

			/* patch the First and Last time stamps in the netflow record to UNIX timestamps
			 * This will be reverted when resending the netflow data, with the costs of loosing 
			 * msec units
			 */
			boot_time  = ((double)(nf_header->unix_secs) + 1e-9 * (double)(nf_header->unix_nsecs)) - 
				(0.001 * (double)(nf_header->SysUptime));
			start_time = (uint32_t)(nf_record->First)/1000 + boot_time;
			end_time   = (uint32_t)(nf_record->Last)/1000 + boot_time;
			nf_record->First = start_time;
			nf_record->Last  = end_time;
			if ( start_time < first_seen )
				first_seen = start_time;
			if ( end_time > last_seen )
				last_seen = end_time;

			if ( verbose ) {
				print_record(nf_record, &string);
				printf("%s", string);
			}
		}
		if ( i != nf_header->count ) {
			syslog(LOG_WARNING, "Expected %i records, but found only %i\n", nf_header->count, i);
			nf_header->count = i;
		}
		writesize = header_length + nf_header->count * record_length;
		write(nffd, (void *)nf_header, writesize);
	}
	free(buff);
	close(nffd);

} /* End of run */

int main(int argc, char **argv) {
 
char	*bindaddr, *pidfile, *filter, *datadir, pidstr[32];
struct stat fstat;
struct sigaction act;
unsigned long	bufflen;
time_t 	twin, t_start, t_tmp;
int		portnum, sock, pidf, err, synctime, daemonize;
char	c;
pid_t	pid;

	portnum  		= verbose = synctime = daemonize = 0;
	bufflen  		= 0;
	netflow_version = 5;
	bindaddr 		= NULL;
	pidfile  		= NULL;
	filter   		= NULL;
	twin	 		= TIME_WINDOW;
	datadir	 		= DEFAULT_DIR;
	strncpy(Ident, "none", 31);
	while ((c = getopt(argc, argv, "whEQVI:DB:b:l:p:P:t:v:")) != EOF) {
		switch (c) {
			case 'h':
				usage(argv[0]);
				exit(0);
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
			case 'Q':
				shut_v5_slow_path = 1;
				break;
			case 'I':
				strncpy(Ident, optarg, 31);
				Ident[31] = 0;
				if ( strchr(Ident, ' ') ) {
					fprintf(stderr,"Ident must not contain spaces\n");
					exit(255);
				}
				break;
			case 'v':
				netflow_version = atoi(optarg);
				if ( netflow_version != 5 && netflow_version != 7 ) {
					fprintf(stderr, "ERROR: Supports only netflow version 5 and 7\n");
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
				pidf = open(pidfile, O_CREAT|O_RDWR, 0644);
				if ( pidf == -1 ) {
					perror("Error opening pid file:");
					exit(255);
				}
				pid = getpid();
				snprintf(pidstr,31,"%i\n", pid);
				write(pidf, pidstr, strlen(pidstr));
				close(pidf);
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
			default:
				usage(argv[0]);
				exit(255);
		}
	}
	if (argc - optind > 1) {
		usage(argv[0]);
		exit(255);
	} else {
		/* user specified a pcap filter */
		filter = argv[optind];
	}

	openlog(argv[0] , LOG_CONS|LOG_PID, SYSLOG_FACILITY);

	sock = Setup_Socket(bindaddr, portnum, bufflen );
	if ( sock == -1 ) 
		exit(255);

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
					perror("Error opening pid file:");
					exit(255);
				}
				snprintf(pidstr,31,"%i\n", pid);
				write(pidf, pidstr, strlen(pidstr));
				close(pidf);
			}
	  		exit (0); /* parent */
		}
	}

	if ( chdir(datadir)) {
		perror("Can't chdir: ");
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

	run(sock, bufflen, twin, t_start);
	close(sock);
	printf("Terminating nfcapd\n");

	if ( pidfile ) 
		unlink(pidfile);

	closelog();
	exit(0);

} /* End of main */
