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
/* The tai and taia routines are based on djb's libtai which is placed in the
 * public domain. See http://cr.yp.to/libtai.html for details. The taia code
 * was slightly modified to only take into account nano-second based timing.
 * All the atto-second related code was removed to save some space when packing
 * taia structures on disk. */

#define _XOPEN_SOURCE	/* needed for strptime */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>

#include "time.h"

void
tai_now(struct tai * t)
{
	tai_unix(t, time((time_t *)0));
}

void
tai_pack(char * s, const struct tai * t)
{
	uint64_t x;

	x = t->x;
	s[7] = x & 255; x >>= 8; 
	s[6] = x & 255; x >>= 8; 
	s[5] = x & 255; x >>= 8; 
	s[4] = x & 255; x >>= 8; 
	s[3] = x & 255; x >>= 8; 
	s[2] = x & 255; x >>= 8; 
	s[1] = x & 255; x >>= 8; 
	s[0] = x;
}

void
tai_unpack(const char * s, struct tai * t)
{
	uint64_t x;

	x = (unsigned char)s[0];
	x <<= 8; x += (unsigned char) s[1];
	x <<= 8; x += (unsigned char) s[2];
	x <<= 8; x += (unsigned char) s[3];
	x <<= 8; x += (unsigned char) s[4];
	x <<= 8; x += (unsigned char) s[5];
	x <<= 8; x += (unsigned char) s[6];
	x <<= 8; x += (unsigned char) s[7];
	t->x = x;
}

void
taia_now(struct taia * t)
{
	struct timeval now;
	gettimeofday(&now, (struct timezone *) 0);
	tai_unix(&t->sec, now.tv_sec);
	t->nano = 1000 * now.tv_usec + 500;
}

void
taia_pack(char * s, const struct taia * t)
{
	unsigned long x;
	
	tai_pack(s, &t->sec);
	s += 8;

	x = t->nano;
	s[3] = x & 255; x >>= 8;
	s[2] = x & 255; x >>= 8;
	s[1] = x & 255; x >>= 8;
	s[0] = x;
}

void
taia_unpack(const char * s, struct taia * t)
{
	unsigned long x;

	tai_unpack(s, &t->sec);
	s += 8;

	x = (unsigned char)s[0];
	x <<= 8; x += (unsigned char)s[1];
	x <<= 8; x += (unsigned char)s[2];
	x <<= 8; x += (unsigned char)s[3];
	t->nano = x;
}

int
taia_less(struct taia * t, struct taia * u)
{
	if (t->sec.x < u->sec.x) return 1;
	if (t->sec.x > u->sec.x) return 0;
	return t->nano < u->nano;
}

int
taia_leq(struct taia * t, struct taia * u)
{
	if (t->sec.x <= u->sec.x) return 1;
	if (t->sec.x > u->sec.x) return 0;
	return t->nano <= u->nano;
}

void
taia_diff(struct taia * t, struct taia * u, struct taia * res)
{
	res->sec.x = u->sec.x - t->sec.x;
	res->nano = u->nano - t->nano;
}

int
timestr_parse(const char * input, struct taia * res, struct taia * b)
{
	struct taia base, * pbase;
	const char * p;
	uint32_t w, d, h, m, s;
	unsigned int n;

	if (!input || !res) return -1;
	if (b) pbase = b;
	else {
		taia_now(&base);
		pbase = &base;
	}
	p = input;
	w = d = h = m = s = 0;

next:
	n = 0;
	while (*p && (*p >= '0' && *p <= '9')) {
		n *= 10;			
		n += (*p-'0');
		p++;
	}
	if (!*p) return -1;

	switch (*p) {
	case 'w':
		if (d*h*m*s) return -1;
		w = n*604800;
		break;
	case 'd':
		if (h*m*s) return -1;
		d = n*86400;
		break;
	case 'h':
		if (m*s) return -1;
		h = n*3600;
		break;
	case 'm':
		if (s) return -1;
		m = n*60;
		break;
	case 's':
		s = n;
		break;
	default:
		return -1;
	}
	if (*++p) goto next;
	
	res->sec.x = pbase->sec.x - (w+d+h+m+s);
	res->nano = pbase->nano;
	
	return 0;
}
