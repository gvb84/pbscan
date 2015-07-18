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
#include <string.h>

#include "sha1.h"

#define BLOCKSIZE 64 /* SHA-1 blocksize */

void
hmac(unsigned char * data, uint32_t datalen, unsigned char * key,
	uint32_t keylen, unsigned char hmac[20])
{
	SHA1_CTX ctx;
	unsigned char k_ipad[BLOCKSIZE], k_opad[BLOCKSIZE];
	unsigned char digest[20]; /* SHA-1 digest is 20 bytes long */
	int i;

	if (keylen > BLOCKSIZE) {
		SHA1Init(&ctx);
		SHA1Update(&ctx, key, keylen);
		SHA1Final(digest, &ctx);

		key = digest;
		keylen = sizeof(digest);
	}


	/* this ensures zero padding if keylen < blocksize */
	memset(k_ipad, 0, sizeof(k_ipad));
	memset(k_opad, 0, sizeof(k_opad));
	memcpy(k_ipad, key, keylen);
	memcpy(k_opad, key, keylen);

	/* XOR key with ipad and opad values */
	for (i=0;i<BLOCKSIZE;i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	SHA1Init(&ctx);
	SHA1Update(&ctx, k_ipad, BLOCKSIZE);
	SHA1Update(&ctx, data, datalen);
	SHA1Final(digest, &ctx);

	SHA1Init(&ctx);
	SHA1Update(&ctx, k_opad, BLOCKSIZE);
	SHA1Update(&ctx, digest, sizeof(digest));
	SHA1Final(hmac, &ctx);

}
