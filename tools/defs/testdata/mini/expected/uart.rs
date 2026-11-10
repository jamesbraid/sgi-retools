// generated from mini abcdef012345 UART_DECODE.h - do not edit, regenerate in mini
//!
//! Made-up UART registers and frame word used to test the
//! decode-header tools.
//!
//! Grades on each item say what is known about it: `established` is what the
//! shipped driver software does, read in full; `inferred` is a reasoned
//! reading; `unknown` is not derived. None of them is a measurement of the
//! silicon.

#![allow(dead_code)]

/// established.
pub const FIFO_DEPTH: u32 = 16;

/// Register `ctl`: read/write, 32-bit; reset 0x0; established.
pub const REG_CTL: u32 = 0x0010;
pub const REG_CTL_WIDTH: u32 = 32;
/// Register `status`: read, 32-bit; reset unknown; established.
pub const REG_STATUS: u32 = 0x0011;
pub const REG_STATUS_WIDTH: u32 = 32;
/// Register `data`: read/write, 8-bit, 16 consecutive registers; reset unknown; inferred.
pub const REG_DATA: u32 = 0x0120;
pub const REG_DATA_WIDTH: u32 = 8;
pub const REG_DATA_COUNT: u32 = 16;

/// Values of `parity` in `Ctl` that the header names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CtlParity {
    /// established.
    None,
    /// established.
    Odd,
    /// inferred.
    Even,
    /// A value the notes do not name.
    Other(u8),
}

impl CtlParity {
    pub const fn from_bits(v: u32) -> Self {
        match v {
            0x0 => Self::None,
            0x1 => Self::Odd,
            0x2 => Self::Even,
            _ => Self::Other(v as u8),
        }
    }

    pub const fn bits(self) -> u32 {
        match self {
            Self::None => 0x0,
            Self::Odd => 0x1,
            Self::Even => 0x2,
            Self::Other(v) => v as u32,
        }
    }
}

/// The `ctl` register word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ctl(u32);

impl Ctl {
    pub const fn new(word: u32) -> Self {
        Self(word)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Bit 0, established.
    pub const fn enable(self) -> bool {
        self.0 & 1 != 0
    }

    /// Bits 3:1, inferred.
    pub const fn parity(self) -> CtlParity {
        CtlParity::from_bits((self.0 >> 1) & 0x7)
    }

    /// Bits 31:16, established.
    pub const fn divisor(self) -> u32 {
        self.0 >> 16
    }
}

/// The `status` register word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status(u32);

impl Status {
    pub const fn new(word: u32) -> Self {
        Self(word)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Bit 0, established.
    pub const fn rx_ready(self) -> bool {
        self.0 & 1 != 0
    }
}

/// The `FRAME` word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame(u32);

impl Frame {
    pub const fn new(word: u32) -> Self {
        Self(word)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Bit 0, established.
    pub const fn start(self) -> bool {
        self.0 & 1 != 0
    }

    /// Bits 8:1, established.
    pub const fn payload(self) -> u32 {
        (self.0 >> 1) & 0xff
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testvec_uart_ctl_40003() {
        let w = Ctl::new(0x40003);
        assert_eq!(w.enable() as u32, 1, "enable");
        assert_eq!(w.parity().bits(), 1, "parity");
        assert_eq!(w.divisor(), 4, "divisor");
    }

    #[test]
    fn testvec_frame_6b() {
        let w = Frame::new(0x6b);
        assert_eq!(w.start() as u32, 1, "start");
        assert_eq!(w.payload(), 53, "payload");
    }

    #[test]
    fn testvec_frame_10() {
        let w = Frame::new(0x10);
        assert_eq!(w.start() as u32, 0, "start");
        assert_eq!(w.payload(), 8, "payload");
    }
}
