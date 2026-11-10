/*
 * UART_DECODE.h - made-up UART (fixture for the decode-header tools)
 *
 *   REG: <BLOCK>.<name> <offset> <acc><width> [count=<n>] reset=<v> <grade>
 *   FIELD: <BLOCK>.<name>.<field> <hi>:<lo> <grade>     a register field
 *   FIELD: <WORD>.<field> <hi>:<lo> <grade>             a non-register word
 *   ENUM: <target> <value> <label> <grade>
 *   TESTVEC: <value> as <WORD or BLOCK.name> => field=val, ...
 */
#ifndef UART_DECODE_H
#define UART_DECODE_H

#include <stdint.h>

#define UART_FIFO_DEPTH 16 /* established */

/* REG: UART.ctl 0x10 rw32 reset=0x0 established */
/* FIELD: UART.ctl.enable 0:0 established */
#define UART_CTL_ENABLE_SHIFT 0
#define UART_CTL_ENABLE_MASK  0x1u
/* FIELD: UART.ctl.parity 3:1 inferred */
#define UART_CTL_PARITY_SHIFT 1
#define UART_CTL_PARITY_MASK  0x7u
/* ENUM: UART.ctl.parity 0 none established */
#define UART_CTL_PARITY_NONE 0
/* ENUM: UART.ctl.parity 1 odd established */
#define UART_CTL_PARITY_ODD 1
/* ENUM: UART.ctl.parity 2 even inferred */
#define UART_CTL_PARITY_EVEN 2
/* FIELD: UART.ctl.divisor 31:16 established */
#define UART_CTL_DIVISOR_SHIFT 16
#define UART_CTL_DIVISOR_MASK  0xffffu

/* REG: UART.status 0x11 r32 reset=unknown established */
/* FIELD: UART.status.rx_ready 0:0 established */
#define UART_STATUS_RX_READY_SHIFT 0
#define UART_STATUS_RX_READY_MASK  0x1u

/* REG: UART.data 0x120 rw8 count=16 reset=unknown inferred */

/* FIELD: FRAME.start 0:0 established */
#define UART_FRAME_START_SHIFT 0
#define UART_FRAME_START_MASK  0x1u
/* FIELD: FRAME.payload 8:1 established */
#define UART_FRAME_PAYLOAD_SHIFT 1
#define UART_FRAME_PAYLOAD_MASK  0xffu

/*
 * TESTVEC: 0x00040003 as UART.ctl => enable=1, parity=1, divisor=4
 */
/*
 * TESTVEC: 0x0000006b as FRAME => start=1, payload=0x35
 */
/*
 * TESTVEC: 0x00000010 as FRAME => start=0, payload=8
 */
/*
 * EXAMPLE (unverified): 0x000000ff as UART.ctl => enable=1, parity=7, divisor=0
 */

#endif
