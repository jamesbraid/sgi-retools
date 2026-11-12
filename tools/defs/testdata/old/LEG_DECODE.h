/*
 * LEG_DECODE.h - made-up legacy-form header (fixture for the importer)
 */
#ifndef LEG_DECODE_H
#define LEG_DECODE_H

#include <stdint.h>

/* FIELD: CMD.class 2:0 established */
#define LEG_CMD_CLASS_SHIFT 0
#define LEG_CMD_CLASS_MASK  0x7u
/* FIELD: CMD.size_field 7:3 inferred */
#define LEG_CMD_SIZEFLD_SHIFT 3
#define LEG_CMD_SIZEFLD_MASK  0x1fu
/* FIELD: CMD.front 31:31 established */
#define LEG_CMD_FRONT_SHIFT 31
#define LEG_CMD_FRONT_MASK  0x1u
#define LEG_CMD_FRONT_INPLACE (0x1u << 31)
#define LEG_CMD_FRONT (1u << 31)
#define LEG_CMD_FRONT_BIT (1u << 31)
#define LEG_CMD_BOTH_BITS (LEG_CMD_FRONT_BIT | 0x1u)

/* FIELD: CMD.format 15:8 established */
#define LEG_CMD_FORMAT_SHIFT 8
#define LEG_CMD_FORMAT_MASK  0xffu
#define LEG_FMT_RGB  1
#define LEG_FMT_RGBA 2 /* inferred */

#define LEG_OP_COPY 0x0e40 /* established: the copy opcode */
#define LEG_OP_WORDS 8
#define LEG_FIELD_GET(w, sh, mk) (((w) >> (sh)) & (mk))

/*
 * TESTVEC: 0x80000102 as CMD => class=2, format=1, front=1
 * CALC: 4 rounded up to even => 4
 */

/* rounds up to an even count */
static inline uint32_t leg_round_even(uint32_t n)
{
    return (n + 1u) & ~1u;
}
#endif
