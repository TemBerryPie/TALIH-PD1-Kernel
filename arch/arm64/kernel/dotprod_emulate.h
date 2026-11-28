/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARM64_DOTPROD_EMULATE_H
#define __ARM64_DOTPROD_EMULATE_H

#define UDOT_VECTOR_MASK	0xbfe0fc00U
#define UDOT_VECTOR_VAL		0x2e809400U

static inline __uint128_t udot_vector_accumulate(__uint128_t dst,
		__uint128_t lhs, __uint128_t rhs, unsigned int lanes)
{
	__uint128_t result = 0;
	unsigned int i;

	for (i = 0; i < lanes; i++) {
		unsigned int acc = (unsigned int)(dst >> (i * 32));
		unsigned int x = (unsigned int)(lhs >> (i * 32));
		unsigned int y = (unsigned int)(rhs >> (i * 32));
		unsigned int j;

		for (j = 0; j < 4; j++) {
			acc += (x & 0xff) * (y & 0xff);
			x >>= 8;
			y >>= 8;
		}
		result |= (__uint128_t)acc << (i * 32);
	}

	return result;
}

#endif
