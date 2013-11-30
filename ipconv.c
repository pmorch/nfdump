/* Copyright (c) 1996 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nffile.h"
#include "util.h"
#include "ipconv.h"

static int	parse_ipv4(const char *src, uint32_t *dst, int *bytes);
static int	parse_ipv6(const char *src, uint64_t *dst, int *bytes);

int parse_ip(int *af, const char *src, uint64_t *dst, int *bytes) {
uint32_t	v4addr;
int ret;

	if ( strchr(src, ':') != NULL )
		*af = PF_INET6;
	else
		*af = PF_INET;

	switch (*af) {
	case AF_INET:
		ret =  (parse_ipv4(src, &v4addr, bytes));
		dst[0] = 0;
		dst[1] = ntohl(v4addr) & 0xffffffffLL ;
		return ret;
		break;
	case AF_INET6:
		ret =  (parse_ipv6(src, dst, bytes));
		dst[0] = ntohll(dst[0]);
		dst[1] = ntohll(dst[1]);
		return ret;
		break;
	}
	/* NOTREACHED */

	return 0;
}

static int parse_ipv4(const char *src, uint32_t *dst, int *bytes) {
static const char digits[] = "0123456789";
int saw_digit, ch;
uint8_t  tmp[4], *tp;

	saw_digit = 0;
	*bytes = 0;
	*(tp = tmp) = 0;
	memset(tmp, 0, sizeof(tmp));
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr(digits, ch)) != NULL) {
			unsigned int new = *tp * 10 + (pch - digits);

			if (new > 255)
				return (0);
			if (! saw_digit) {
				if (++(*bytes) > 4)
					return (0);
				saw_digit = 1;
			}
			*tp = new;
		} else if (ch == '.' && saw_digit) {
			if (*bytes == 4)
				return (0);
			*++tp = 0;
			saw_digit = 0;
			if ( !(*src) )
				return 0;
		} else
			return (0);
	}

	memcpy(dst, tmp, sizeof(tmp));
	return (1);
}

static int parse_ipv6(const char *src, uint64_t *dst, int *bytes) {
static const char xdigits_l[] = "0123456789abcdef",
		  xdigits_u[] = "0123456789ABCDEF";
uint8_t tmp[16], *tp, *endp, *colonp;
const char *xdigits, *curtok;
int ch, saw_xdigit;
u_int val;

	memset((tp = tmp), '\0', sizeof(tmp));
	endp = tp + sizeof(tmp);
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			} else if (*src == '\0') {
				return (0);
			}
			if (tp + sizeof(uint16_t) > endp)
				return (0);
			*tp++ = (u_char) (val >> 8) & 0xff;
			*tp++ = (u_char) val & 0xff;
			saw_xdigit = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + 4) <= endp) &&
		    parse_ipv4(curtok, (uint32_t *)tp, bytes) > 0) {
			tp += 4;
			saw_xdigit = 0;
			break;	/* '\0' was seen by parse_ipv4(). */
		}
		return (0);
	}
	if (saw_xdigit) {
		if (tp + sizeof(uint16_t) > endp)
			return (0);
		*tp++ = (u_char) (val >> 8) & 0xff;
		*tp++ = (u_char) val & 0xff;
	}
	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = tp - colonp;
		int i;

		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	*bytes = 16 - ( endp - tp );
		
	memcpy(dst, tmp, sizeof(tmp));
	return (1);
}

/*
int main( int argc, char **argv ) {

char	*s, t[64];
uint64_t	anyaddr[2];
int af, ret, bytes;
	
	s = argv[1];
	ret = parse_ip(&af, s, anyaddr, &bytes);
	if ( ret != 1 ) {
		printf("Parse failed!\n");
		exit(0);
	}

	if ( af == PF_INET ) 
		inet_ntop(af, &(((uint32_t *)anyaddr)[3]), t, 64);
	else
		inet_ntop(af, anyaddr, t, 64);

	printf("Convert back: %s => %s %i bytes\n", s, t, bytes);

}

*/
