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
#ifndef TLS_H
  #define TLS_H

/* list of TLS alert/error codes so some more user-friendly decoding
   is possible when doing a TLS scan */

struct {
	int code;
	const char * desc;
} tls_error_codes[] = {
	{10,"Unexpected message"},
	{20,"Bad record MAC"},
	{21,"Decryption failed"},
	{22,"Record overflow"},
	{30,"Decompression failure"},
	{40,"Handshake failure"},
	{41,"No certificate"},
	{42,"Bad certificate"},
	{43,"Unsupported certificate"},
	{44,"Certificate revoked"},
	{45,"Certificate expired"},
	{46,"Certificate unknown"},
	{47,"Illegal parameter"},
	{48,"Unknown CA"},
	{49,"Access denied"},
	{50,"Decode error"},
	{51,"Decrypt error"},
	{60,"Export restriction"},
	{70,"Protocol version"},
	{71,"Insufficient security"},
	{80,"Internal error"},
	{90,"User canceled"},
	{100,"No renegotiation"},
	{110,"Unsupported extension"},
	{111,"Certificate unobtainable"},
	{112,"Unrecognized name"},
	{113,"Bad certificate status response"},
	{114,"Bad certificate hash value"},
	{115,"Unknown PSK identity"},
	{120,"No Application Protocol"},
	{0, NULL}
};

#endif
