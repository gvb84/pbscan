/*
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <limits.h>
#include <sys/wait.h>
#define __USE_BSD 1
#define __FAVOR_BSD 1
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/route.h>

#include <pcap/pcap.h>

#include <pthread.h>

/* uinet specific includes */
#include "uinet_api.h"
#define EV_STANDALONE 1
#define EV_UINET_ENABLE 1
#include "libuinet/lib/libev/ev.h"

/* local includes */
#include "utils.h"
#include "range.h"
#include "hmac.h"
#include "route.h"
#include "time.h"
#include "tls.h"
#include "version.h"

/* system wide globals used for stdout/stderr redirection */
FILE * out = NULL; 			/* stdout file stream */
FILE * err = NULL; 			/* stderr file stream */

/* static globals used by the scanner */
static int raw_fd = -1; 		/* raw fd used to send raw packets */
static uint32_t rand_seed = 0;		/* random seed */
static struct ip_range ip_range; 	/* range of IPs to scan */
static struct port_range * port_range;	/* range of ports to scan */
static uint32_t src_ip; 		/* source IP in network order */
static uint32_t bcast_ip;		/* broadcast IP in network order */
static uint32_t gw_ip;			/* gateway IP in network order */
static uint32_t mask_ip;		/* network mask in network order */
static double timeout;			/* timeout in seconds */
static int quit = 0;			/* shutting down if set to non-zero*/
static int scanner_done = 0;		/* scanner done if set to non-zero */
static struct tai scanner_done_time;	/* time that scanner was done */
static int force_hex_output = 0;	/* force hexadecimal output */
static int verbose = 0;			/* show verbose output */
static char scan_mode = 0;		/* scan mode to use */
static char * gateway;			/* IP addr of the gateway as string */
static struct ev_loop * loop;		/* libev event loop reference */
static unsigned char * custom_data;	/* data sent for custom scan */
static size_t custom_data_len;		/* length of custom data */
static ev_timer scanner_break;		/* timer to break out of event loop */
static useconds_t sleep_between_pkts;	/* time to sleep between probes */
pthread_t threads[1];			/* thread references */
static uint16_t	ip_id_value;		/* IP ID value for the probes */
static uint8_t ip_ttl_value;		/* IP TTL value for the probes */
static uint16_t	tcp_win_value;		/* TCP Window value for the probes */


/* stat counters */
static size_t total_syn_sent;	
static size_t total_syn_todo;
static size_t total_ack_received;
static size_t total_open_ports_found;
static size_t total_active_connections;

/* secret key data used in HMAC to detecting valid reply's to our probes */
#define SECRET_KEYSZ 8 /* must be multiple of 4 */
static unsigned char secret_key[SECRET_KEYSZ];

/* IP tables rule to set/unset dropping of TCP RST packets */
#define IPTABLES	"/sbin/iptables"
#define IPTABLES_ARG	{IPTABLES, "-D", "OUTPUT", "-p", "tcp", \
	"--tcp-flags", "RST", "RST", "-j", "DROP", NULL}

/* HTTP probe used for HTTP scan mode */
#define HTTP_PROBE	"GET / HTTP/1.0\r\n\r\n"
#define HTTP_PROBE_LEN	strlen(HTTP_PROBE)

/* TLS1.0 probe used for SSL scan mode with zero timestamp and options */
#define SSL_PROBE	"\x16\x03\x01\x00\x2c\x01\x00\x00\x28\x03\x01\x00" \
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
			"\x00"
#define SSL_PROBE_LEN	49

/* default ports; ftp,ssh,smtp,http,pop2,pop3,imap2,imap3,mysql,mssql */
#define DEFAULT_PORTRANGE	"21,22,25,80,109,110,143,220,3306,1433"

/* output macro's */
#define WARN(...) do { fprintf(out, "[!] "); fprintf(out, __VA_ARGS__); \
	fprintf(out, "\n"); fflush(out); } while (0);
#define OUT(...) do { fprintf(out, __VA_ARGS__); } while (0);
#define VERBOSE(...) do { if (!verbose) break; fprintf(out, __VA_ARGS__); \
	fflush(out); } while(0);

/* used to calculate TCP/IP checksum */
struct pseudohdr {
	uint32_t src;
	uint32_t dst;
	uint8_t mbz;
	uint8_t proto;
	uint16_t len;
};

/* holds callback state for the connections we're setting up */
struct connection {
	ev_uinet watcher;
	struct uinet_socket * so;
	struct ev_uinet_ctx * soctx;
	struct tai ts;
	int counted;
};

/* standard TCP/IP checksum routine */
static unsigned short
csum(unsigned short * buf, size_t nwords)
{
	unsigned long sum;

	for (sum=0; nwords > 0; nwords--) {
		sum += *buf++;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short)(~sum);
}

/* 
 * Calculates HMAC and truncates it to a 32-bit cookie with the input
 * consisting of the 4-tuple identifying the connection (src and destination
 * IPs and ports).
*/
static inline uint32_t
calc_cookie(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport)
{
	unsigned char buf[12], output[20];

	memset(buf, 0, sizeof(buf));
	*(uint32_t *)buf = src;
	*(uint32_t *)(&buf[4]) = dst;
	*(uint16_t *)(&buf[8]) = sport;
	*(uint16_t *)(&buf[10]) = dport;

	hmac(buf, sizeof(buf), secret_key, sizeof(secret_key), output);

	return *(uint32_t *)output;
}

/*
 * wrapper over the uinet UIO and IOV infrastructure so we can
 * simply supply a buffer and a length and get it written out to
 * the supplied socket
 */
int
socket_write(struct uinet_socket * so, void * buf, size_t len)
{
	struct uinet_uio uio;
	struct uinet_iovec iov;

	uio.uio_iov = &iov;
	iov.iov_base = buf;
	iov.iov_len = len;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = iov.iov_len;
	return uinet_sosend(so, NULL, &uio, 0);
}

/*
 * Send a TCP packet over the raw file descriptor pointed to by 'fd' with the 
 * connection's 4-tuple identified by src/dst for the IP's and sport/dport
 * for the port numbers respectively. The TCP sequence and acknowledgement
 * numbers can also be supplied. Please note that all arguments are assumed
 * to already be in network byte order so no conversion in this function will
 * be done anymore.
 */
static void
send_pkt(int fd, uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport,
	uint32_t seq, uint32_t ack)
{
	struct tcphdr * tcph;
	struct ip * iph;
	struct pseudohdr * psh;
	struct sockaddr_in sin;
	char buf[4096];
	int ret;

	memset(buf, 0, sizeof(buf));

	iph = (struct ip *)(buf);	
	iph->ip_hl = 5;
	iph->ip_v = 4;
	iph->ip_tos = 0;	
	iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
	iph->ip_id = ip_id_value;
	iph->ip_off = 0;
	iph->ip_ttl = ip_ttl_value;
	iph->ip_p = IPPROTO_TCP;
	iph->ip_sum = 0;
	iph->ip_src.s_addr = src;
	iph->ip_dst.s_addr = dst;
	
	tcph = (struct tcphdr *)(buf + sizeof(struct ip));
	tcph->th_sport = sport;
	tcph->th_dport = dport;
	tcph->th_seq = seq;
	tcph->th_ack = ack;
	tcph->th_off = 5;
	tcph->th_x2 = 0;
	tcph->th_flags = TH_SYN;
	tcph->th_win = tcp_win_value;
	tcph->th_sum = 0;
	tcph->th_urp = 0;	

	psh = (struct pseudohdr *)(buf + sizeof(struct ip) + 
		sizeof(struct tcphdr));
	psh->src = iph->ip_src.s_addr;
	psh->dst = iph->ip_dst.s_addr;
	psh->mbz = 0;
	psh->proto = iph->ip_p;
	psh->len = ntohs(tcph->th_off << 2);
	
	tcph->th_sum = csum((unsigned short*)tcph, 
		sizeof(struct tcphdr) + sizeof(struct pseudohdr));

	sin.sin_family = AF_INET;
	sin.sin_port = tcph->th_dport;
	sin.sin_addr = iph->ip_dst;
	memset(&sin.sin_zero, 0, sizeof(sin.sin_zero));

	ret = sendto(fd, buf, iph->ip_len, 0, (struct sockaddr *)&sin,
		sizeof(sin));
	if ( ret < 0) pfatal("sendto");
}

/* scanner thread */
static void *
scanner(void * arg)
{
	uint32_t i, j, seq, ack, dst_ip;
	uint16_t sport, dport;
	struct port_range * next;
	
	/* calculate total number of packets that have to be sent
	   this number will be slightly 
	 */
	next = port_range;
	while (next) {
		total_syn_todo += (next->end - next->start + 1);
		next = next->next;
	}
	total_syn_todo *= (ip_range.end-ip_range.start+1);

	/* correct the count for broadcast and network addresses if needed */
	if (ntohl(bcast_ip) >= ip_range.end && ntohl(bcast_ip)
		<= ip_range.start) total_syn_todo--;
	if (ntohl((src_ip & mask_ip)) >= ip_range.end &&
		ntohl((src_ip & mask_ip)) <= ip_range.end) total_syn_todo--;

	VERBOSE("total SYN probes to sent: %zu\n", total_syn_todo);

	/* loop over the IP range to scan and then for each IP loop over the
	   port ranges that we want to scan */
	for (i=ip_range.start; i<=ip_range.end; i++) {

		dst_ip = htonl(i);

		/* ignore broadcast IP or network mask IP */
		if (dst_ip == bcast_ip || dst_ip == (src_ip & mask_ip)) {
			continue;
		}

		next = port_range;
		while (next) {
			for (j=next->start; j<=next->end; j++) {
				dport = htons(j);

				/* make sure source port is not privileged */
				sport = htons(10000 + (rand_r(&rand_seed)
					% SHRT_MAX));

				/* set random ACK value */
				ack = htonl(rand_r(&rand_seed) % UINT_MAX);

				/* calculate cookie and set it as the
			           sequence number */
				seq = htonl(calc_cookie(src_ip, dst_ip,
					sport, dport));

				/* send out the packet */
				send_pkt(raw_fd, src_ip, dst_ip,
					sport, dport, seq, ack);

				total_syn_sent++;

				if (sleep_between_pkts) {
					usleep(sleep_between_pkts);
				}
			}
			next = next->next;
		}
	}

	/* signal that the scanner is done sending packets */
	scanner_done = 1;
	tai_now(&scanner_done_time);

	pthread_exit(NULL);
	return 0;
}

inline static int
min(int a, int b) {
	return (a < b ? a : b);
}

inline static void
output_data(unsigned char * buf, size_t len)
{
	unsigned char * p, * endp;
	size_t i, j;
	int dohex = 0;

	/* output in hex if that is a forced mode or if we only find
	   printable characters and CR and LF (which we will strip out() */
	endp = buf + len;
	p = buf;
	if (!force_hex_output) {
		while (p < endp) {
			if (!isprint(*p) && *p != '\r' && *p != '\n')
				break;
			p++;
		}
		dohex = (p != endp);
	}
	else dohex = 1;

	if (!dohex) {
		p = buf;
		while (p < endp) {
			if (*p == '\r' || *p == '\n') {
				*p = 0;	
				break;
			}
			p++;
		}
		OUT("%s", buf);
		return;
	}

	/* try to parse a possible TLS response if in TLS scanning mode */
	if (scan_mode == 'T' && !force_hex_output && len >= 7) {

		/* TLS fatal alert message received */
		if (buf[0] == 0x15 && buf[1] == 0x3 &&
				buf[3]==0x0 && buf[4]==0x2 && buf[5]==0x2) {
			OUT("TLSv1.%u alert received: (", buf[2]-1);

			for (i=0;i<sizeof(tls_error_codes)/sizeof(tls_error_codes[0]);i++) {
				if (buf[6] == tls_error_codes[i].code) {
					OUT("%s", tls_error_codes[i].desc);
					break;
				}
			}
			if (tls_error_codes[i].code==0) OUT("unknown");
			OUT(")");
			return;
		}
	}

	OUT("\n");
	for (i=0;i<(len/16);i++) {
		OUT("%.5zx  ", i*16);
		for (j=0;j<16&&i*16+j<len;j++) {
			if (j==8) OUT(" ");
			OUT("%02x ", buf[i*16+j]);
		}
		OUT(" ");
		for (j=0;j<16&&i*16+j<len;j++) {
			OUT("%c",
				isprint(buf[i*16+j])
				?buf[i*16+j]:'.');
		}
		OUT("\n");
	}

	i*=16;
	j = i;
	OUT("%.5zx  ", i);
	for(;i<len;i++) {
		if (!(i%8) && i>j) OUT(" ");
		OUT("%02x ", buf[i]);
	}
	OUT(" ");
	for(i=0;i<16-(len%16);i++) {
		if (i==7) OUT(" ");
		OUT("   ");
	}
	for(i=j;i<len;i++) {
		OUT("%c", isprint(buf[i])?buf[i]:'.');
	}
	OUT("\n");
}

static void
connection_cb(struct ev_loop * loop, ev_uinet * w, int revents)
{
	struct tai now;
	unsigned char buffer[64*1024];
	char addrbuf[32];
	struct connection * conn = NULL;
	struct uinet_iovec iov;
	struct uinet_uio uio;
	struct uinet_in_conninfo inc;
	int max_read, max_write, read_size, error;

	max_read = uinet_soreadable(w->so, 0);
	max_write = uinet_sowritable(w->so, 0);

	conn = w->data;

	/* If this connection wasn't counted yet count it now; counting
	   is being done here to avoid duplicate connection counting
	   as it's quite likely to get several ACKs for one probe if
	   the userland stack hasn't had enough time to catch up yet. */
	if (!conn->counted) {
		total_open_ports_found++;
		conn->counted = 1;
	}

	uinet_sogetconninfo(conn->so, &inc);	
	tai_now(&now);

	memset(buffer, 0, sizeof(buffer));

	if (scan_mode == 'B' || max_read != 0)
		OUT("%s:%u", uinet_inet_ntoa(inc.inc_ie.ie_faddr, addrbuf,
			sizeof(addrbuf)), ntohs(inc.inc_ie.ie_fport));

	if (max_read == -1) {
		tai_now(&now);

		OUT(" (t/o: %zus)\n", (size_t)(now.x - conn->ts.x));

		ev_uinet_stop(loop, &conn->watcher);
		uinet_soclose(conn->so);
		ev_uinet_detach(conn->soctx);
		total_active_connections--;
		free(conn);
		
		return;
	}
	else if (max_read) {
		OUT(" -> ");
		read_size = min(min(max_read, max_write), sizeof(buffer));

		uio.uio_iov = &iov;
		iov.iov_base = buffer;
		iov.iov_len = read_size;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = read_size;

		error = uinet_soreceive(w->so, NULL, &uio, NULL);
		if (0 != error) {
			OUT("(read error: %d, closing)\n", error);
		}
		else {
			if (iov.iov_len > sizeof(buffer))
				iov.iov_len = sizeof(buffer);
			output_data(buffer, iov.iov_len);
			OUT("\n");
		}	
		ev_uinet_stop(loop, &conn->watcher);
		uinet_soclose(conn->so);
		ev_uinet_detach(conn->soctx);
		free(conn);
		total_active_connections--;
		return;
	}

	error = 0;
	/* in banner scan mode we don't expect to get here */
	if (scan_mode == 'B') {
		WARN("nothing to read; shouldnt happen\n");
		return;
	}
	/* send HTTP scan probe */
	else if (scan_mode == 'H') {
		error = socket_write(conn->so, HTTP_PROBE, HTTP_PROBE_LEN);
	}

	/* send SSL scan probe */
	else if (scan_mode == 'T') {
		error = socket_write(conn->so, SSL_PROBE, SSL_PROBE_LEN);
	}

	/* send custom scan probe */
	else if (scan_mode == 'C') {
		error = socket_write(conn->so, custom_data, custom_data_len);
	}

	if (error) {
		WARN("%s:%u (error when sending probe)\n",
			uinet_inet_ntoa(inc.inc_ie.ie_faddr, addrbuf,
			sizeof(addrbuf)), ntohs(inc.inc_ie.ie_fport));
	}

	/* we sent our probe so now we just wait for receiving data only */
	ev_uinet_stop(loop, &conn->watcher);
	ev_uinet_set(&conn->watcher, conn->soctx, EV_READ);
	ev_uinet_start(loop, &conn->watcher);
}

static void
sniffer_cb(char * reject, const struct pcap_pkthdr * h, 
	const unsigned char * bytes)
{
	char buf[32];
	struct uinet_in_addr in;
	struct uinet_sockaddr_in sin;
	struct uinet_socket * so;
	struct ev_uinet_ctx * soctx;
	struct connection * conn;
	struct ip * iph;
	struct tcphdr * tcph;
	struct ether_header * eth;
	uint32_t cookie, ack;
	uint16_t iplen, iphlen;
	size_t len;
	int ret;

	/* only support EtherNET frames */
	len = h->caplen;
	if (len < sizeof(struct ether_header)) return;
	eth = (struct ether_header *)bytes;

	/* check if it's an IP frame */
	if (ntohs(eth->ether_type) != 0x800) return;

	len -= sizeof(struct ether_header);	
	bytes += sizeof(struct ether_header);
	if (len < sizeof(struct ip)) return;
	iph = (struct ip *)bytes;

	/* check if it's a TCP packet */
	if (iph->ip_p != IPPROTO_TCP) return;

	/* check IP length fields */
	iplen = ntohs(iph->ip_len);
	iphlen = iph->ip_hl << 2;
	if (iplen > len || iphlen > len)  return;
	
	len -= iphlen;
	bytes += iphlen;
	if (len < sizeof(struct tcphdr)) return;
	tcph = (struct tcphdr *)(bytes);

	/* only care about SYN|ACK packets */
	if ((tcph->th_flags & (TH_SYN|TH_ACK)) != (TH_SYN|TH_ACK)) {
		return;
	}

	/* 4-tuple arguments are switched as it should be a reply */
	cookie = calc_cookie(iph->ip_dst.s_addr, iph->ip_src.s_addr,
		tcph->th_dport, tcph->th_sport);

	/* compare ACKs if it matches it's a reply to one of our probes */
	ack = ntohl(tcph->th_ack) - 1;
	if (ack != cookie) {
		/* invalid SYN|ACK received so reject it */
		*reject = 1;
		return;
	}

	in.s_addr = iph->ip_src.s_addr;
	memset(buf, 0, sizeof(buf));
	uinet_inet_ntoa(in, buf, sizeof(buf));
	VERBOSE("open port found at: %s:%u (cookie: 0x%x, ttl: %u)\n", buf,
		ntohs(tcph->th_sport), cookie, iph->ip_ttl);

	total_ack_received++;

	/* create a non-blocking uinet socket */
	memset(&sin, 0, sizeof(struct uinet_sockaddr_in));
	sin.sin_len = sizeof(struct uinet_sockaddr_in);
	sin.sin_family = UINET_AF_INET;
	sin.sin_addr.s_addr = iph->ip_src.s_addr;
	sin.sin_port = tcph->th_sport;
	ret = uinet_socreate(uinet_instance_default(), UINET_PF_INET, &so,
		UINET_SOCK_STREAM, UINET_IPPROTO_TCP);
	if (ret) {
		WARN("uinet_socreate failed");
		return;
	}	
	uinet_sosetnonblocking(so, 1);

	ret = uinet_fake_soconnect(so, (struct uinet_sockaddr *)&sin,
		tcph->th_dport, htonl(ack));
	if (ret && ret != UINET_EADDRINUSE) {
		WARN("fake uinet connect failed: %i", ret);
		return;
	}

	soctx = ev_uinet_attach(so);
	if (NULL == soctx) {
		WARN("ev_uinet_attach failed\n");
		return;
	}

	/* create new connection and attach it to the event loop */
	conn = malloc(sizeof(*conn));
	if (!conn) pfatal("malloc");
	conn->soctx = soctx;
	conn->so = so;
	conn->counted = 0;
	tai_now(&conn->ts);
	ev_init(&conn->watcher, connection_cb);
	ev_uinet_set(&conn->watcher, conn->soctx, 
		scan_mode == 'B' ? EV_READ : EV_WRITE);
	conn->watcher.data = conn;
	ev_uinet_start(loop, &conn->watcher);

	total_active_connections++;
}

static void
scanner_break_cb(EV_P_ ev_timer * w, int events)
{
	VERBOSE("playing Queen; I want to break freeeheee!!!...\n");

	ev_break(EV_A_ EVBREAK_ONE);
}

static void
scanner_done_cb(EV_P_ ev_timer * w, int events)
{
	struct tai now;

	if (scanner_done) {

		tai_now(&now);

		/* give the grabber thread 1 second to catch up on incoming
		   ACKs and if no ACKs have come in and there are no active
		   connections left bail out immediately */
		if (now.x - scanner_done_time.x >= 1 &&
			!total_active_connections) {
			VERBOSE("scanner is done and no active sockets left\n");
			ev_break(EV_A_ EVBREAK_ONE);
		}
		
		/* if it's not set yet set the timeout for the final break out
		   of the event loop regardless of how many active connections
		   are still open */
		if (!ev_is_active(&scanner_break)) {
			VERBOSE("scanner is done... cleaning up remaining sockets\n");
			ev_timer_init(&scanner_break, scanner_break_cb,
				timeout, 0);
			ev_timer_start(loop, &scanner_break);
		}
	}
}

static void
scanner_stdin(EV_P_ ev_io * w, int events)
{
	char buf[4096];

	read(STDIN_FILENO, &buf, sizeof(buf));	

	OUT("sent: %2.2f%% (of %zu), open: %zu, active: %zu, acks: %zu\n",
		total_syn_todo?(
			(double)total_syn_sent/
			(double)total_syn_todo * 100.0):0.0,
		total_syn_todo,
		total_open_ports_found,
		total_active_connections,
		total_ack_received
		);
}

static void
scanner_start_cb(EV_P_ ev_timer * w, int events)
{
	if (pthread_create(&threads[0], NULL, scanner, NULL))
		pfatal("pthread_create");
}

static void *
grabber(void * arg)
{
	ev_timer scanner_done_watcher, scanner_start_watcher;
	ev_io stdin_watcher;
	const char * iface = (char *)arg;
	char * ip, * bcast, * mask;
	int ret;

	/* get interface information */
	ret = get_iface_addrs(iface, &ip, &bcast, &mask);
	if (ret < 0) {
		fprintf(err, "error while getting interface addresses!\n");
		return NULL;
	}
	src_ip = inet_addr(ip);
	bcast_ip = inet_addr(bcast);
	mask_ip = inet_addr(mask);

	/* setup uinet */
	ret = uinet_init(32, 128*1024, NULL);
	if (ret) {
		fprintf(err, "error while initting libuinet\n");
		return NULL;
	}
	uinet_install_sighandlers();

	/* construct PCAP interface on the right interface with the right
	   settings such that uinet can start capturing packets for us */
	ret = uinet_ifcreate(uinet_instance_default(), UINET_IFTYPE_PCAP, iface,
		"iface", 1, 1, NULL); /* first 1 is cdom */
	if (ret) {
		fprintf(err, "error while creating iface\n");
		return NULL;
	}
	ret = uinet_interface_add_alias(uinet_instance_default(), "iface", 
		ip, bcast, mask);
	free(ip);
	free(bcast);
	free(mask);
	if (ret) {
		fprintf(err, "error while adding iface alias\n");
		return NULL;
	}
	ret = uinet_interface_up(uinet_instance_default(), "iface", 0, 0);
	if (ret) {
		fprintf(err, "cannot put up interface\n");
		return NULL;
	}
	ret = uinet_if_set_pcap_handler(uinet_instance_default(), "iface", sniffer_cb);
	if (ret) {
		fprintf(err, "error while setting pcap handler\n");
		return NULL;
	}

	/* set route information in uinet */
	route(gateway);

	VERBOSE("done setting up uinet... starting event loop\n");

	loop = ev_default_loop(0);

	VERBOSE("created default loop!!\n");

	/* check every 1/2 second whether scanner thread is done */
	ev_timer_init(&scanner_done_watcher, scanner_done_cb, 0.5, 1);
	ev_timer_start(loop, &scanner_done_watcher);

	/* ugly but needed to kick off scanner after event loop is set up */
	ev_timer_init(&scanner_start_watcher, scanner_start_cb, 0.01, 0);
	ev_timer_start(loop, &scanner_start_watcher);

	/* read from stdin for printing of stats */
	ev_io_init(&stdin_watcher, scanner_stdin, 0, EV_READ);
	ev_io_start(loop, &stdin_watcher);

	VERBOSE("started running main event loop\n");
	ev_run(loop, 0);

	VERBOSE("done with main event loop\n");

	/* clean up */
	ev_default_destroy();
	uinet_shutdown(0);

	return NULL;
}

static void
exec_iptables(char ** argvp)
{
	int ret, status;
	pid_t pid;

	pid = fork();
	if (pid == -1) pfatal("fork");
	if (!pid) {
		ret = execve(IPTABLES, argvp, NULL);
		if (ret < 0) pfatal("execve");
		exit(EXIT_FAILURE);
	}

	ret = waitpid(pid, &status, 0);
	if (ret == -1) pfatal("waitpid");

	if (!WIFEXITED(status)) {
		fatal("iptables execution failed");
	}
	ret = WEXITSTATUS(status);
	if (ret) {
		fatal("iptables execution returned error code");
	}
}

inline static void
set_iptables_rule()
{
	char * argvp[] = IPTABLES_ARG;
	argvp[1] = "-A";
	exec_iptables(argvp);
}

inline static void
unset_iptables_rule()
{
	char * argvp[] = IPTABLES_ARG;
	argvp[1] = "-D";
	exec_iptables(argvp);
}

static void
sig_handler(int sig)
{
	quit = 1;
}

static void
usage(const char * arg0)
{
	fprintf(stderr, "%s [options] <target>\n\n", arg0);
	fprintf(stderr, "  target can be specified as:\n");
	fprintf(stderr, "   10.1.2.3; 10.0.0.2-10.0.255.255; 10.0.0.1/24\n\n");
	fprintf(stderr, "Main options:\n");
	fprintf(stderr, "-sB/sH/sT/sC     - scan mode (default: -sB)\n");
	fprintf(stderr, "  Modes: B=Banner, H=HTTP, T=TLS, C=Custom\n");
	fprintf(stderr, "-p <portlist>    - list of ports to scan\n");
	fprintf(stderr, "  Ex: -p22; -p21-80,443,1024-2048,8080\n");
	fprintf(stderr, "-b <limit>       - outgoing bandwidth limit\n");
	fprintf(stderr, "  Ex: -b300k; -b67m; -b500b (300kbps, 67mbps, ");
	fprintf(stderr, "500bps)\n");
	fprintf(stderr, "-d <file>        - file containing data to send ");
	fprintf(stderr, "(-sC only)\n");
	fprintf(stderr, "-t <timeout>     - timeout in seconds (default: 30)\n");
	fprintf(stderr, "-v               - verbose output\n");
	fprintf(stderr, "-x               - always output banners in hex mode");
	fprintf(stderr, "\n\nAuxiliary options:\n");
	fprintf(stderr, "-i <iface>       - capture interface to use\n");
	fprintf(stderr, "-r <seed>        - random seed to use (can be in decimal or hex)\n");
	fprintf(stderr, "-T <ttl>         - IP TTL (default: 64)\n");
	fprintf(stderr, "-W <win>         - TCP Window size (default: 65535)\n");
	fprintf(stderr, "-I <id>          - IP ID (default: 12345)\n");
	fprintf(stderr, "-n               - neglect setting RST drop rule\n");
	fprintf(stderr, "-o               - show internal uinet output\n");
	fprintf(stderr, "-h               - this screen\n");    
	fprintf(stderr, "\n");
	fflush(stderr);
	exit(EXIT_FAILURE);
}

int
main(int argc, char ** argv)
{
	char * portrange_str = DEFAULT_PORTRANGE;
	char * iface = NULL, * gw = NULL, * ip = NULL;
	char * bw_end = NULL, * bw_arg = NULL;
	char * custom_data_fn = NULL;
	long int j, mult = 0;
	int c, i, ret, seed_set, status, outfd, errfd;
	int redirout, setiptables;
	struct sigaction sa;
	pid_t pid;

	/* set the iptables rule and redirect stdout by default */
	setiptables = 1;
	redirout = 1;

	/* no seed set by default */
	seed_set = 0;

	out = stdout;
	err = stderr;

	/* set default probe values */
	ip_id_value = htons(54321);
	ip_ttl_value = 64;
	tcp_win_value = htons(65535);

	/* default scan mode is the banner scan */
	scan_mode = 'B';

	/* default timeout in seconds */
	timeout = 30.0;

	fprintf(out, "polarbearscan %s -- gvb@santarago.org\n\n",
		polarbearscan_version);

	while ((c = getopt(argc, argv, "vnohxi:r:p:s:b:t:d:I:T:W:")) != -1) {
		switch (c) {
		case 'I':
			errno = 0;
			j = strtol(optarg, NULL, 10);
			if (errno || j < 0 || j > 65535) {
				fprintf(stderr, "invalid IP ID value\n");
				usage(argc > 0 ? argv[0] : "(unknown)");
			}
			ip_id_value = htons(j);
			break;
		case 'T':
			errno = 0;
			j = strtol(optarg, NULL, 10);
			if (errno || j < 0 || j > 255) {
				fprintf(stderr, "invalid IP TTL value\n");
				usage(argc > 0 ? argv[0] : "(unknown)");
			}
			ip_ttl_value = j;
			break;
		case 'W':
			errno = 0;
			j = strtol(optarg, NULL, 10);
			if (errno || j < 0 || j > 65535) {
				fprintf(stderr, "invalid TCP Window value\n");
				usage(argc > 0 ? argv[0] : "(unknown)");
			}
			tcp_win_value = htons(j);
			break;
		case 'd':
			custom_data_fn = optarg;
			break;
		case 'b':
			bw_arg = optarg;
			break;
		case 's':
			scan_mode = *optarg;
			if (scan_mode != 'B' && scan_mode != 'H'
					&& scan_mode != 'T'
					&& scan_mode != 'C') {
				fprintf(stderr, "invalid scan mode\n");
				usage(argc > 0 ? argv[0] : "(unknown)");
			}
			break;
		case 'p':
			portrange_str = optarg;
			break;
		case 'i':
			iface = optarg;
			break;
		case 'r':
			errno = 0;
			/* support hex (prefixed with 0x) and decimal */
			j = strtol(optarg, NULL, 
				(strlen(optarg) > 2 &&
				*optarg=='0' && *optarg+1=='x') ? 16 : 0);
			if (errno) {
				fprintf(stderr, "invalid seed\n");
				usage(argc > 0 ? argv[0] : "(unknown)");
			}
			rand_seed = (uint32_t)j;
			seed_set = 1;
			break;
		case 'n':
			setiptables = 0;
			break;
		case 'o':
			redirout = 0;
			break;
		case 'x':
			force_hex_output = 1;
			break;
		case 't':
			errno = 0;
			j = strtol(optarg, NULL, 0);
			if (errno) {
				fprintf(stderr, "invalid timeout\n");
				usage(argc > 0 ? argv[0] : "(unknown)");
			}
			if (j < 0 || j > (5*60))
				fatal("maximum timeout is 5 minutes");
			timeout = (double)j;
			break;	
		case 'v':
			verbose = 1;
			break;
		case 'h':
		default:
			usage(argc > 0 ? argv[0] : "(unknown)");
			break;
		}
	}

	/* parse target IP range */
	if (optind == argc) fatal("no target IP-range specified");
	ret = iprange_parse(argv[optind], &ip_range);	
	if (ret < 0) fatal("error while parsing IP-range");

	/* parse target port range */
	ret = portrange_parse(portrange_str, &port_range);
	if (ret < 0) fatal("error while parsing port range");

	/* load custom data from file if needed */ 
	if (scan_mode == 'C') {
		if (!custom_data_fn) 
			fatal("-sC cannot be used without -d");

		/* 128kB should be more than enough */
		custom_data_len = 128*1024;
		ret = read_full_file(custom_data_fn, &custom_data,
			&custom_data_len, 1);
		if (ret < 0) fatal("cannot read data file");
	}
	else if (custom_data_fn) {
		fatal("-d can only be used in conjuction with -sC");
	}

	/* parse bandwith limitation option if set */
	if (bw_arg) {
		if (!strlen(bw_arg)) fatal("invalid bandwidth option");
		c = tolower(bw_arg[strlen(bw_arg)-1]);
		switch (c) {
		case 'b':
			mult = 1;
			break;
		case 'k':
			mult = 1024;
			break;
		case 'm':
			mult = (1024*1024);
			break;
		case 'g':
			mult = (1024*1024*1024);
			break;
		default:
			fatal("invalid bandwidth option");
		}
		bw_arg[strlen(bw_arg)-1]=0;
		errno = 0;
		j = strtol(bw_arg, &bw_end, 0);
		if (errno != 0 || bw_end != bw_arg+strlen(bw_arg))
			fatal("error while parsing bandwidth option");
		if (!j) fatal("cannot set bandwidth to 0 bytes per second");

		/* frame size for each SYN probe is 64 bytes (minimum
		   size of Ethernet frame) so we calculate the amount of
		   time we need to sleep in between probes such that we
		   end up at the required bandwidth usage.
		*/
		sleep_between_pkts = ((1000000 / (j * mult))*64);

		if (sleep_between_pkts > 5000000) {
			fatal("bandwidth limit set too low");
		}
	}

	/* detect interface and/or gateway if necessary */
	ret = get_default_gw(&iface, &gw);
	if (ret < 0) fatal("cannot detect interface and gateway");
	gateway = gw;
	gw_ip = inet_addr(gateway);

	/* I don't really care about proper randomness; I'd rather
	   be able to reproduce exact packet output by being able to
           to reuse the same seed so everywhere just use rand_r() 
	   for generation PRNG values.
        */
	if (!seed_set) {
		rand_seed = get_rand_uint32();
	}

	/* output settings used for this scan */
	fprintf(out, "seed: 0x%x, iface: %s, src: ", rand_seed, iface);
	ret = get_iface_addrs(iface, &ip, NULL, NULL);
	if (ret < 0) fatal("error while getting interface addresses!\n");
	fprintf(out, "%s (id: %u, ttl: %u, win: %u)\n", ip,
		ntohs(ip_id_value), ip_ttl_value, ntohs(tcp_win_value));
	free(ip);

	if (scan_mode == 'C') {
		VERBOSE("using %zu bytes of data for custom scan\n",
			custom_data_len);	
	}

	/* get a secret key */
	for (i=0;i<SECRET_KEYSZ;i+=4) {
		j = rand_r(&rand_seed);	
		secret_key[i] = j & 0xff;
		secret_key[i+1] = ((j >> 8) & 0xff);	
		secret_key[i+2] = ((j >> 16) & 0xff);	
		secret_key[i+3] = ((j >> 24) & 0xff);	
	}

	/* If we need to set the IP tables firewall entry to drop RST packets
	   we need to setup a parent process such that we can monitor the child
	   and remove the IP table entry when the child is done. This is pretty
	   dirty but barring any abnormal termination of the parent (SIGSEGV
	   f.e.) it will properly remove the firewall entry. */
	if (setiptables) {
		pid = fork();
		if (pid == -1) pfatal("fork");
		if (pid) {

			/* set the IP tables entry */
			set_iptables_rule();

			/* install signal handler */
			sa.sa_handler = sig_handler;
			sigemptyset(&sa.sa_mask);
			sa.sa_flags = 0;
			if (sigaction(SIGINT, &sa, NULL) == -1)
				pfatal("sigaction");
			if (sigaction(SIGTERM, &sa, NULL) == -1)
				pfatal("sigaction");

			/* wait until child is done or we're killed  */
			do {
				ret = waitpid(pid, &status, 0);
				if (quit) break;
			} while (ret == EINTR || (!WIFEXITED(status) &&
				!WIFSIGNALED(status)));

			/* if we're killed terminate the child too */
			if (quit) {
				ret = kill(pid, SIGTERM);
				if (ret < 0) pfatal("kill");
				do {
					ret = waitpid(pid, &status, 0);
				} while (!WIFEXITED(status) && 
					!WIFSIGNALED(status));
			}

			/* reset the IP tables */
			unset_iptables_rule();
			exit(EXIT_SUCCESS);
		}	
	}

	/* hide libuinet stdout/stderr if necessary */
	if (redirout) {
		ret = close(0);
		if (ret < 0) pfatal("close"); 
		outfd = dup(1);
		if (outfd < 0) pfatal("dup");
		errfd = dup(2);
		if (errfd < 0) pfatal("dup");
		ret = close(1);
		if (ret < 0) pfatal("close"); 
		ret = close(2);
		if (ret < 0) pfatal("close"); 
		out = fdopen(outfd, "w");
		if (!out) fatal("fdopen");
		err = fdopen(errfd, "w");
		if (!err) fatal("fdopen");
	}

	/* get raw socket for pumping out SYN packets */
	raw_fd = get_raw_fd();

	/* run grabber thread which captures the packets */
	grabber((void *)iface);

	/* clean up after ourselves */
	for (i=0;i<sizeof(threads)/sizeof(pthread_t);i++) {
		pthread_join(threads[i], NULL);
	}

	OUT("done\n");


	exit(EXIT_SUCCESS);
}
