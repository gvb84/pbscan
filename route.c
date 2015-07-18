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

/* This is all a bit funky and simply ripped from the internals
   of the libuinet as tracing down the nest of includes needed
   to define the proper structures (rt_metrics and such) when
   including sys/net/route.h turned out to be too painful.
*/

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "uinet_api.h"
#include "utils.h"

#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

struct rt_metrics {
	u_long	rmx_locks;	/* Kernel must leave these values alone */
	u_long	rmx_mtu;	/* MTU for this path */
	u_long	rmx_hopcount;	/* max hops expected */
	u_long	rmx_expire;	/* lifetime for route, e.g. redirect */
	u_long	rmx_recvpipe;	/* inbound delay-bandwidth product */
	u_long	rmx_sendpipe;	/* outbound delay-bandwidth product */
	u_long	rmx_ssthresh;	/* outbound gateway buffer limit */
	u_long	rmx_rtt;	/* estimated round trip time */
	u_long	rmx_rttvar;	/* estimated rtt variance */
	u_long	rmx_pksent;	/* packets sent using this route */
	u_long	rmx_weight;	/* route weight */
	u_long	rmx_filler[3];	/* will be used for T/TCP later */
};

struct rt_msghdr {
	u_short	rtm_msglen;	/* to skip over non-understood messages */
	u_char	rtm_version;	/* future binary compatibility */
	u_char	rtm_type;	/* message type */
	u_short	rtm_index;	/* index for associated ifp */
	int	rtm_flags;	/* flags, incl. kern & message, e.g. DONE */
	int	rtm_addrs;	/* bitmask identifying sockaddrs in msg */
	pid_t	rtm_pid;	/* identify sender */
	int	rtm_seq;	/* for sender to identify action */
	int	rtm_errno;	/* why failed */
	int	rtm_fmask;	/* bitmask used in RTM_CHANGE message */
	u_long	rtm_inits;	/* which metrics we are initializing */
	struct	rt_metrics rtm_rmx; /* metrics themselves */
};

#define RTM_ADD		0x1	/* Add Route */
#define RTM_CHANGE	0x3

#define RTM_VERSION	5	/* Up the ante and ignore older versions */
#define RTA_DST		0x1	/* destination sockaddr present */
#define RTA_GATEWAY	0x2	/* gateway sockaddr present */
#define RTA_NETMASK	0x4	/* netmask sockaddr present */
#define RTA_GENMASK	0x8	/* cloning mask sockaddr present */
#define RTA_IFP		0x10	/* interface name sockaddr present */
#define RTA_IFA		0x20	/* interface addr sockaddr present */
#define RTA_AUTHOR	0x40	/* sockaddr for author of redirect */
#define RTA_BRD		0x80	/* for NEWADDR, broadcast or p-p dest addr */

#define RTF_GATEWAY	0x2

extern int socket_write(struct uinet_socket *, void *, size_t);

void
route(const char * gw)
{
	int ret;
	struct uinet_socket * so;
	struct rt_msghdr * rtm;
	struct uinet_sockaddr * sa;
	struct uinet_sockaddr_in * sin;
	char buf[4096];

	errno = 0;
	ret = uinet_socreate(uinet_instance_default(), UINET_PF_ROUTE, &so, UINET_SOCK_RAW, 0);
	if (ret) {
		errno = ret;
		pfatal("uinet_socreate");
	}

	memset(buf, 0, sizeof(buf));

	rtm = (struct rt_msghdr *)buf;
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = RTM_ADD;
	rtm->rtm_flags = RTF_GATEWAY;
	rtm->rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
	rtm->rtm_pid = getpid();
	rtm->rtm_seq = 1234;

	sa = (struct uinet_sockaddr *)(rtm + 1);
	sin = (struct uinet_sockaddr_in *)(sa);
	sin->sin_len = sizeof(struct uinet_sockaddr_in);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = inet_addr("0.0.0.0");

	sa = (struct uinet_sockaddr *)((unsigned char *)(sa) + ROUNDUP(sa->sa_len));
	sin = (struct uinet_sockaddr_in *)(sa);
	sin->sin_len = sizeof(struct uinet_sockaddr_in);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = inet_addr(gw);

	sa = (struct uinet_sockaddr *)((unsigned char *)(sa) + ROUNDUP(sa->sa_len));
	sin = (struct uinet_sockaddr_in *)(sa);
	sin->sin_len = 0;
	sin->sin_family = AF_INET;

	sa = (struct uinet_sockaddr *)((unsigned char *)(sa) + ROUNDUP(sa->sa_len));
	rtm->rtm_msglen = (char *)sa - buf;

	errno = socket_write(so, buf, rtm->rtm_msglen);
	if (errno) pfatal("socket_write");

	/* probably should loop through reply messages and see whether 
	   the setting of the route succeeded; right now we just assume
	   it worked. */

	return;
}
