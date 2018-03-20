use std::mem;

#[derive(Clone, Copy)]
pub enum ArmCondition {
    EQ = 0b0000,
    
    NE = 0b0001,
    
    HS = 0b0010,
    
    LO = 0b0011,
    
    MI = 0b0100,
    
    PL = 0b0101,
    
    VS = 0b0110,
    
    VC = 0b0111,
    
    HI = 0b1000,
    
    LS = 0b1001,
    
    GE = 0b1010,
    
    LT = 0b1011,
    
    GT = 0b1100,
    
    LE = 0b1101,
    
    AL = 0b1110,
    
    NV = 0b1111,
}

impl ArmCondition {
  pub fn find(self, value: u32) -> ArmCondition {
    unsafe { mem::transmute(value as u8) }
  }
}

pub enum ArmOpcode {
    Invalid,
    
    // Branches.
    B,  // PC += offs
    BL, // LR = PC-4, PC += offs
    BX, // PC +=
    
    // Arithmetic.
    ADD, // D = Op1 + Op2
    ADC, // D = Op1 + Op2 + carry
    SUB, // D = Op1 - Op2
    SBC, // D = Op1 - Op2 + carry - 1
    RSB, // D = Op2 - Op1
    RSC, // D = Op2 - Op1 + carry - 1
    
    // Comparisons.
    CMP, // Op1 - Op2, only flags set
    CMN, // Op1 + Op2, only flags set
    TST, // Op1 & Op2, only flags set
    TEQ, // Op1 ^ Op2, only flags set
    
    // Logical Operations.
    AND, // D = Op1 & Op2
    EOR, // D = Op1 ^ Op2
    ORR, // D = Op1 | Op2
    BIC, // D = Op1 & !Op2, i.e. bit clear
    
    // Data Movement.
    MOV, // D = Op2
    MVN, // D = !Op2
    
    // Multiplication.
    MUL,  // Rd = Rm * Rs
    MLA,  // Rd = (Rm * Rs) + Rn
    MULL, // RdHi_RdLo = Rm * Rs
    MLAL, // RdHi_RdLo = (Rm * Rs) + RdHi_RdLo
    
    // Load/Store Instructions.
    LDR,  // Load word.
    STR,  // Store word.
    LDRH, // Load signed/unsigned halfword.
    STRH, // Store signed/unsigned halfword.
    LDRB, // Load signed/unsigned byte.
    STRB, // Store signed/unsigned byte.
    
    // Block data transfer.
    LDM,  // Load multiple words.
    STM,  // Store multiple words.
    
    // PSR transfer.
    MRS,
    MSR,
}