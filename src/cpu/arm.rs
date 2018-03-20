pub const ARM_SP: usize = 13;
pub const ARM_LR: usize = 14;
pub const ARM_PC: usize = 15;

#[derive(Clone, Copy, PartialEq)]
pub enum ExecutionMode {
  Arm = 0,
	Thumb = 1,
}

pub enum WordSize {
  Arm = 4,
	Thumb = 2,
}

#[derive(Clone, Copy)]
pub enum PrivilegeMode {
	User = 0b10000,
	Fiq = 0b10001,
	Irq = 0b10010,
	Supervisor = 0b10011,
	Abort = 0b10111,
	Undefined = 0b11011,
	System = 0b11111,
}

enum ExceptionVectors {
  Reset = 0x00000000,                 // Supervisor.
  UndefinedInstruction = 0x00000004,  // Undef.
  SoftwareInderrupt = 0x00000008,     // Supervisor.
  AboutPrefetch = 0x0000000C,         // Abort.
  AbortData = 0x00000010,             // Abort.
  Reserved = 0x00000014,              // Reserved.
  Irq = 0x00000018,                   // IRQ.
  Fiq = 0x0000001C,                   // FIQ.
}

#[derive(Clone, Copy)]
pub struct ProgramStatusRegister {
    pub n: bool,           // 31 // Negative result from ALU flag.
    pub z: bool,           // 30 // Zero result from ALU flag.
    pub c: bool,           // 29 // ALU operation carried out.
    pub v: bool,           // 28 // ALU operation overflowed

    pub dummy: [bool; 20], // 27-8 //Useless bits, but added for more accuracy emulation.

    pub i: bool,           // 7 // Disable the IRQ.
    pub f: bool,           // 6 // Disable the FIQ.

    pub t: bool,           // 5 // Architecture the CPU. // 0 - ARM, 1 - THUMB.

    pub m: PrivilegeMode,      // 4-0 // Define the processor mode.

}

impl ProgramStatusRegister {
    pub fn new() -> ProgramStatusRegister {
        ProgramStatusRegister {
            n: false,
            z: false,
            c: false,
            v: false,

            dummy: [false; 20],

            i: true,
            f: true,

            t: false,

            m: PrivilegeMode::System,
        }
    }
}

// Instead ERAM & IRAM maybe?
struct ArmMemory(u32);

struct ArmBoard(u32);
