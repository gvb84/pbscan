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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

extern FILE * err;

void
fatal(const char * line)
{
	fprintf(err, "%s\n", line);
	fflush(err);
	exit(EXIT_FAILURE);
}

void
pfatal(const char * line)
{
	perror(line);
	fflush(err);
	exit(EXIT_FAILURE);
}

int
get_raw_fd()
{
	int fd, ret, one;

	fd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (fd < 0) pfatal("socket");
	
	one = 1;
	ret = setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
	if (ret < 0) pfatal("setsockopt");

	return fd;
}

int
get_default_gw(char ** iface, char ** gw)
{
	FILE * f;
	char line[100], * ret, * p, * striface = NULL, * strgw = NULL;
	struct in_addr in;
	int check_iface;

	check_iface = (iface && *iface && strlen(*iface) > 0);

	f = fopen("/proc/net/route", "r");
	if (!f) return -1;

	while (!feof(f)) {
		ret = fgets(line, 100, f);
		if (!ret) return -1;

		p = line;
		while (*p && *p != ' ' && *p != '\t') p++;
		if (!*p) continue;
		*p++ = 0;

		if (check_iface && strcmp(*iface, line))
			continue;

		while (*p && (*p == ' ' || *p == '\t')) p++;
		if (!*p) continue;
		ret = p;

		while (*p && *p != ' ' && *p != '\t') p++;
		if (!*p) continue;
		*p++ = 0;

		if (strcmp(ret, "00000000")) continue;
		
		ret = p;
		while (*p && *p != ' ' && *p != '\t') p++;
		if (!*p) continue;
		*p++ = 0;

		in.s_addr = strtol(ret, NULL, 16);

		if (iface) {
			striface = strdup(line);
			if (!striface) goto errout;
		}

		if (gw) {
			strgw = strdup(inet_ntoa(in));
			if (!strgw) goto errout;
		}

		*iface = striface;
		*gw = strgw;

		return 0;
	}

errout:
	if (striface) free(striface);
	if (strgw) free(strgw);

	return -1;
}

int
get_iface_addrs(const char * iface, char ** ip, char ** bcast, char ** mask)
{
	char * strip = NULL, * strbcast = NULL;
	struct sockaddr_in * sin;
	struct ifreq ifr;
	int fd, ret;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return -1;

	memset(&ifr, 0, sizeof(struct ifreq));
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);

	sin = (struct sockaddr_in *)&ifr.ifr_addr;

	/* IP */
	if (ip) {
		ret = ioctl(fd, SIOCGIFADDR, &ifr);
		if (ret < 0) goto errout;
		strip = strdup(inet_ntoa(sin->sin_addr));
		if (!strip) goto errout;
	}

	/* broadcast */
	if (bcast) {
		ret = ioctl(fd, SIOCGIFBRDADDR, &ifr);
		if (ret < 0) goto errout;
		strbcast = strdup(inet_ntoa(sin->sin_addr));
		if (!strbcast) goto errout;
	}

	/* netmask */
	if (mask) {
		ret = ioctl(fd, SIOCGIFNETMASK, &ifr);
		if (ret < 0) goto errout;
		*mask = strdup(inet_ntoa(sin->sin_addr));
		if (!*mask) goto errout;
	}

	if (bcast) *bcast = strbcast;
	if (ip) *ip = strip;

	close(fd);
	return 0;
errout:
	close(fd);
	if (strip) free(strip);
	if (strbcast) free(strbcast);
	return -1;
}

uint32_t
get_rand_uint32()
{
	uint32_t val;
	int fd, ret;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0) pfatal("cannot open /dev/urandom");

	ret = read(fd, &val, sizeof(uint32_t));
	if (ret != sizeof(uint32_t)) {
		pfatal("error while reading from /dev/urandom");
	}

	ret = close(fd);
	if (ret < 0) pfatal("error while closing /dev/urandom");

	return val;
}

/* This utility opens the file pointed to by filename fn and tries to read
   in either the full contents of the file or up to *sz (or the full length
   of the file; whichever is less) if max is set to non-zero. It will return
   -1 in the case of an error. If succeeded *output will be set to a pointer
   to the buffer containing the contents of the file and *sz will be set to
   the total amount data read in. */
int
read_full_file(const char * fn, unsigned char ** output, size_t * sz, int max)
{
	FILE * fd;
	unsigned char * buf, * buf2;
	size_t alloc = 1024, total, read;
	int ret;

	if (!output) return -1;
	fd = fopen(fn, "r");
	if (!fd) return -1;

	buf = malloc(alloc);
	if (!buf) return -1;

	total = 0;
	while (!feof(fd)) {
		read = max ? (*sz - total) : (alloc-total);
		if (read > (alloc-total)) read = alloc-total;
		read = fread(buf+total, 1, read, fd);
		if (ferror(fd)) goto err;
		total += read;	
		if (feof(fd)) break;
		if (total == alloc) {
			alloc <<= 2;
			buf2 = realloc(buf, alloc);
		 	if (!buf2) goto err;
			buf = buf2;
		}
		if (max && !(*sz-total)) break;
	}

	ret = fclose(fd);	
	if (ret < 0) goto err;

	*sz = total;
	*output = buf;
	return 0;
err:
	free(buf);
	return -1;
}
