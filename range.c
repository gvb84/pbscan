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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "range.h"

static inline int
ip_parse(const char * input, uint32_t * res, size_t * resconsumed)
{
	uint32_t ip1, ip2, ip3, ip4;
	size_t left, consumed;
	int ret;

	if (!input || !res) return -1;

	left = strlen(input);
	if (left > 255) return -1; /* input unreasonably long */

	ret = sscanf(input, "%u.%u.%u.%u%zn", &ip1, &ip2, &ip3, &ip4,
		&consumed);
	if (ret != 4) return -1;
	if ((ip1 | ip2 | ip3 | ip4) & (~255)) return -1;

	/* leave IP in host order */
	*res = (ip1 << 24) | (ip2 << 16) | (ip3 << 8) | ip4;
	if (resconsumed) *resconsumed = consumed;

	return 0;
}

int
iprange_parse(char * input, struct ip_range * res)
{
	uint32_t ipstart, ipend, netmask, n;
	size_t consumed, left;
	int ret, i;

	if (!input || !res) return -1;

	consumed = 0;
	left = strlen(input);
	ret = ip_parse(input, &ipstart, &consumed);
	if (ret < 0) return -1;

	/* only single IP specified */
	if (consumed == left) {
		res->start = ipstart;
		res->end = ipstart;
		return 0;
	}

	left -= (consumed + 1);
	input += consumed;

	if (*input == '-') {
		ret = ip_parse(++input, &ipend, &consumed);
		if (ret < 0) return -1;
		if (ipstart > ipend) {
			res->start = ipend;
			res->end = ipstart;
		}
		else {
			res->start = ipstart;
			res->end = ipend;
		}
		return 0;
	}
	else if (*input != '/') return -1;

	/* check if netmask is specified in bitmask notation /xx or in
	   IP notation /x.x.x.x f.e. and parse accordingly */
	ret = ip_parse(++input, &ipend, &consumed);
	if (!ret) {
		if (consumed != left) return -1;

		/* find ones following zeroes */
		n = 0;
		for (i=0;i<32;i++) {
			if (!(ipend & (1 << (31-i)))) n=1;
			else if (n==1) return -1;
		}
		netmask = ipend;
		if (netmask == 0xffffffff) {
			res->start = res->end = ipstart;
			return 0;
		}
	}
	else {
		ret = sscanf(input, "%u%zn", &n, &consumed);
		if (ret != 1 || n < 1 || n > 32 || left != consumed)
			return -1;
		netmask = 0;
		for (i=0; i<n;i++) {
			netmask |= (1 << (31-i));
		}	
		if (netmask == 0xffffffff) {
			res->start = res->end = ipstart;
			return 0;
		}
		/*
			network:   ipstart & netmask
			broadcast: ipstart | ~netmask
		*/
	}

	res->start = ((ipstart & netmask) | 0x1);
	res->end = ((ipstart | ~netmask) & ~0x1);

	if (res->start > res->end) {
		ipend = res->start;
		res->start = res->end;
		res->end = ipend;
	}

	return 0;
}

void
portrange_free(struct port_range * range)
{
	struct port_range * next;
	if (!range) return;
	next = range->next;
	while (next) {
		next = next->next;
		free(range);
	}
}

int
portrange_parse(char * input, struct port_range ** res)
{
	struct port_range * first, * range = NULL;
	char * p;
	int current = 0, start = -1, end = -1;

	if (!input || !res) return -1;

	first = malloc(sizeof(struct port_range));
	if (!first) return -1;
	first->next = NULL;

	range = first;
	p = input;
	while (*p) {
		current = 0;
		while (*p && *p >= '0' && *p <= '9') {
			current *= 10;
			current += (*p - '0');
			p++;
		}	
		if (current >= 65536) goto err;
		if (*p == ',') {
			if (start == -1) start = current;
			else if (end == -1) end = current;
			if (end > 0 && end < start) {
				goto err;
			}
			range->start = start;
			range->end = (end == -1 ? start : end);
			range->next = malloc(sizeof(struct port_range));
			range = range->next;
			range->next = NULL;
			start = end = -1;
		}
		else if (*p == '-') {
			if (start == -1) start = current;
		}
		else if (!*p) {
			if (start == -1) start = current;
			if (end == -1) end = current;
			range->start = start;
			range->end = end;
		}
		p++;
	}

	/* empty string */
	if (start == end && start == -1 && first == range) return -1;

	*res = first;
	return 0;
err:
	if (range) portrange_free(range);
	return -1;
}
