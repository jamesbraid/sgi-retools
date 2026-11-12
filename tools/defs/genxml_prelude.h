/*
 * Stand-in for Mesa's agx_pack_header.h, so the output of the vendored
 * gen_pack.py compiles without Mesa's util headers. It defines the helpers the
 * generated code calls with the same meaning: pack by shifting into a 64-bit
 * value, unpack across 32-bit words, and the bounds, mask and exact checks.
 * Written for this repository; it is not part of the vendored files.
 */
#pragma once

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define GLOBAL
#define CONST const
#define UNUSED __attribute__((unused))
#define ALIGN_POT(x, pot_align) (((x) + (pot_align) - 1) & ~((pot_align) - 1))
#define IS_POT_NONZERO(v) ((v) != 0 && ((v) & ((v) - 1)) == 0)

static inline uint64_t
util_bitpack_uint(uint64_t v, uint32_t start, UNUSED uint32_t end)
{
   return v << start;
}

static inline uint64_t
util_bitpack_sint(int64_t v, uint32_t start, uint32_t end)
{
   const int bits = end - start + 1;
   const uint64_t mask = bits == 64 ? ~0ull : ((1ull << bits) - 1);
   return ((uint64_t)v & mask) << start;
}

static inline uint64_t
__gen_unpack_uint(CONST uint32_t *restrict cl, uint32_t start, uint32_t end)
{
   uint64_t val = 0;
   const int width = end - start + 1;
   const uint64_t mask = (width == 64) ? ~((uint64_t)0) : ((uint64_t)1 << width) - 1;

   for (unsigned word = start / 32; word < (end / 32) + 1; word++) {
      val |= ((uint64_t)cl[word]) << ((word - start / 32) * 32);
   }

   return (val >> (start % 32)) & mask;
}

static inline int64_t
__gen_unpack_sint(CONST uint32_t *restrict cl, uint32_t start, uint32_t end)
{
   const int size = end - start + 1;
   uint64_t val = __gen_unpack_uint(cl, start, end);
   return size == 64 ? (int64_t)val : (int64_t)(val << (64 - size)) >> (64 - size);
}

static inline void
agx_genxml_validate_bounds(const char *name, uint64_t value, uint64_t bound)
{
   if (value >= bound) {
      fprintf(stderr, "%s out-of-bounds, got 0x%" PRIx64 ", max %" PRIx64 "\n", name, value, bound);
      abort();
   }
}

static inline bool
agx_genxml_validate_mask(FILE *fp, const char *name, const void *cl_, uint32_t index, uint32_t bad_mask)
{
   const uint32_t *cl = (const uint32_t *)cl_;
   uint32_t bad = cl[index] & bad_mask;

   if (bad && fp != NULL)
      fprintf(fp, "XXX: Unknown field of %s unpacked at word %u got %X, bad mask %X\n", name, index, cl[index], bad);

   return bad == 0;
}

static inline bool
agx_genxml_validate_exact(FILE *fp, const char *name, uint64_t value, uint64_t exact)
{
   if (value != exact && fp != NULL)
      fprintf(fp, "XXX: Expected %s to equal %" PRIx64 " but got %" PRIx64 "\n", name, value, exact);

   return value == exact;
}
