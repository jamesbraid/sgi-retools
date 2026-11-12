# UART notes (fixture)

The control register sits at 0x10 and the status register follows it.
The divisor is held in bits 31:16 of the control word, parity in bits 3:1.
A frame carries the payload in bits 8:1 after one start bit.
Known words: 0x00040003 (control), 0x0000006b (frame) and 0x00000010 (frame).
