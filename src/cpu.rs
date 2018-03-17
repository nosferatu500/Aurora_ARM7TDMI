use interconnect::Interconnect;

#[derive(Clone, Copy)]
struct StatusRegister {
    pub N: bool, // 31 // Negative result from ALU flag.
    pub Z: bool, // 30 // Zero result from ALU flag.
    pub C: bool, // 29 // ALU operation carried out.
    pub V: bool, // 28 // ALU operation overflowed

    pub M: u8, // 4-0 // Define the processor mode.

    pub I: bool, // 7 // Disable the IRQ.
    pub F: bool, // 6 // Disable the FIQ.

    pub T: bool, // 5 // Architecture the CPU. // 0 - ARM, 1 - THUMB.
}

impl StatusRegister {
    pub fn new() -> StatusRegister {
        StatusRegister {
            N: false,
            Z: false,
            C: false,
            V: false,

            M: 0b10011,

            I: true,
            F: true,

            T: false,
        }
    }
}

pub struct Cpu {
    pc: u32, // r15 // program counter
    regs: [u32; 16],

    current_pc: u32,

    interconnect: Interconnect,

    sp: u32, // r13 // stack pointer
    lr: u32, // r14 // link register

    cpsr: StatusRegister, // Current program status register.
    spsr: StatusRegister, // Saved program status register. // Only for privileged mode.

    r8_fiq: u32,
    r9_fiq: u32,
    r10_fiq: u32,
    r11_fiq: u32,
    r12_fiq: u32,

    sp_fiq: u32,
    lr_fiq: u32,
    spsr_fiq: StatusRegister,

    sp_svc: u32,
    lr_svc: u32,
    spsr_svc: StatusRegister,

    sp_abt: u32,
    lr_abt: u32,
    spsr_abt: StatusRegister,

    sp_irq: u32,
    lr_irq: u32,
    spsr_irq: StatusRegister,

    sp_und: u32,
    lr_und: u32,
    spsr_und: StatusRegister,
}

impl Cpu {
    pub fn new(interconnect: Interconnect) -> Cpu {
        let pc = 0;
        Cpu {
            pc,
            regs: [0xdeadbeef; 16],

            current_pc: pc,

            interconnect,

            sp: 0,

            lr: 0,

            cpsr: StatusRegister::new(),
            spsr: StatusRegister::new(),

            r8_fiq: 0,
            r9_fiq: 0,
            r10_fiq: 0,
            r11_fiq: 0,
            r12_fiq: 0,

            sp_fiq: 0,
            lr_fiq: 0,
            spsr_fiq: StatusRegister::new(),

            sp_svc: 0,
            lr_svc: 0,
            spsr_svc: StatusRegister::new(),

            sp_abt: 0,
            lr_abt: 0,
            spsr_abt: StatusRegister::new(),

            sp_irq: 0,
            lr_irq: 0,
            spsr_irq: StatusRegister::new(),

            sp_und: 0,
            lr_und: 0,
            spsr_und: StatusRegister::new(),
        }
    }

    pub fn reset(&mut self) {
      self.lr_svc = self.pc;
      self.pc = 0;

      self.spsr_svc = self.cpsr;
      self.cpsr = StatusRegister::new();

      let sp = 13 as usize;
      let lr = 14 as usize;
      let pc = 15 as usize;

      self.regs[sp] = 0;
      self.regs[lr] = 0;
      self.regs[pc] = 0;

      self.cpsr.T = false;

      self.cpsr.I = true;
      self.cpsr.F = true;

      self.cpsr.M = 0b10011;
      
    }

    fn set_reg(&mut self, index: u32, value: u32) {
        self.regs[index as usize] = value;
    }

    fn get_reg(&mut self, index: u32) -> u32 {
        self.regs[index as usize]
    }

    pub fn run_next_instruction(&mut self) {
        let pc = self.pc;

        let instruction = self.interconnect.load32(self.pc);

        self.current_pc = pc;

        match instruction >> 5 & 1 {
          0b0 => {
            self.pc = pc.wrapping_add(4);
            self.decode32(instruction);

            self.cpsr.T = false;
          },

          0b1 => {
            self.pc = pc.wrapping_add(2);
            self.decode16(instruction as u16);

            self.cpsr.T = true;
          },
          _ => unreachable!(),
        }
    }

    fn get_operand2_shift(&mut self, shift: u32, rm: u32) -> u32 {
        match shift & 0b1 {
            0 => {
                let amount = shift >> 3 & 0x1f;
                let operation_type = shift >> 1 & 0b11;

                match operation_type {
                    0b00 => return rm << amount,
                    0b01 => return rm >> amount,
                    0b10 => return ((rm as i32) >> amount) as u32,
                    0b11 => return rm.rotate_right(amount),
                    _ => panic!("Unexpected operation type {}", operation_type),
                }
            }

            1 => {
                //Rs
                let amount = shift >> 4 & 0xf;
                let operation_type = shift >> 1 & 0b11;

                match operation_type {
                    0b00 => return rm << amount,
                    0b01 => return rm >> amount,
                    0b10 => return ((rm as i32) >> amount) as u32,
                    0b11 => return rm.rotate_right(amount),
                    _ => panic!("Unexpected operation type {}", operation_type),
                }
            }

            _ => panic!("Unexpected shift type"),
        };
    }

    fn get_operand2_rotate(&mut self, rotate: u32, imm: u32) -> u32 {
        imm.rotate_right(rotate * 2)
    }

    fn decode32(&mut self, instruction: u32) {
        let condition = instruction >> 28;
        let opcode = (instruction >> 25) & 0b1111;

        let i = instruction >> 26 & 0b1;
        let s = instruction >> 21 & 0b1;

        let rn = instruction >> 20 & 0b1111;
        let rd = instruction >> 16 & 0b1111;

        // Operand 2 section:
        // IF i == 0
        let shift = instruction >> 4 & 0xff;
        let rm = instruction & 0b1111;

        // IF i == 1
        let rotate = instruction >> 8 & 0b1111;
        let imm = instruction & 0xff;

        let operand2 = match i {
            0 => self.get_operand2_shift(shift, rm),
            1 => self.get_operand2_rotate(rotate, imm),
            _ => panic!("Unexpected operand"),
        };

        println!("Instruction: {:032b} \t {:#x}", instruction, instruction);

        match condition {
            0b0000 => self.cpsr.Z = true,
            0b0001 => self.cpsr.Z = false,
            0b0010 => self.cpsr.C = true,
            0b0011 => self.cpsr.C = false,
            0b0100 => self.cpsr.N = true,
            0b0101 => self.cpsr.N = false,
            0b0110 => self.cpsr.V = true,
            0b0111 => self.cpsr.V = false,
            0b1000 => {
                self.cpsr.C = true;
                self.cpsr.Z = false;
            }
            0b1001 => {
                self.cpsr.C = false;
                self.cpsr.Z = true;
            }
            0b1010 => self.cpsr.N = self.cpsr.V,
            0b1011 => self.cpsr.N = !self.cpsr.V,
            0b1100 => {
                self.cpsr.Z = false;
                self.cpsr.N = self.cpsr.V;
            }
            0b1101 => {
                self.cpsr.Z = true;
                self.cpsr.N = !self.cpsr.V;
            }
            0b1110 => (),
            0b1111 => return,
            _ => panic!("\n\nUnknown condition {:04b}\n\n", condition),
        }

        match opcode {
            0b0000 => self.op_and(rd, rn, operand2),
            0b0001 => self.op_eor(rd, rn, operand2),
            0b0010 => self.op_sub(rd, rn, operand2),
            0b0011 => self.op_rsb(rd, rn, operand2),
            0b0100 => self.op_add(rd, rn, operand2),
            0b0101 => self.op_adc(rd, rn, operand2),
            0b0110 => self.op_sbc(rd, rn, operand2),
            0b0111 => self.op_rsc(rd, rn, operand2),
            0b1000 => self.op_tst(rn, operand2),
            0b1001 => self.op_teq(rn, operand2),
            0b1010 => self.op_cmp(rn, operand2),
            0b1011 => self.op_cmn(rn, operand2),
            0b1100 => self.op_orr(rd, rn, operand2),
            0b1101 => self.op_mov(rd, operand2),
            0b1110 => self.op_bic(rd, rn, operand2),
            0b1111 => self.op_mvn(rd, operand2),
            _ => panic!("\n\nUnknown opcode {:04b}\n\n", opcode),
        }
    }

    fn decode16(&mut self, instruction: u16) {
        let thumb_format = instruction >> 13;

        println!("Instruction: {:016b} \t {:#x}", instruction, instruction);

        // Format I & II
        if thumb_format == 0b000 {
            let opcode = instruction >> 11 & 0b11;

            let offset = instruction >> 6 & 0x1f;

            let rs = instruction >> 3 & 0b111;

            let rd = instruction & 0b11;

            match opcode {
                0b00 => {
                    let res = self.get_reg(rs as u32) << offset;
                    self.set_reg(rd as u32, res);
                }
                0b01 => {
                    let res = self.get_reg(rs as u32) >> offset;
                    self.set_reg(rd as u32, res);
                }
                0b10 => {
                    let res = (self.get_reg(rs as u32) as i32) >> offset;
                    self.set_reg(rd as u32, res as u32);
                }
                0b11 => {
                    let opcode = instruction >> 9 & 0b11;

                    let rn = instruction >> 6 & 0b111;

                    match opcode {
                        0b00 => {
                            let res = self.get_reg(rs as u32) + self.get_reg(rn as u32);
                            self.set_reg(rd as u32, res);
                        }
                        0b01 => {
                            let res = self.get_reg(rs as u32) - self.get_reg(rn as u32);
                            self.set_reg(rd as u32, res);
                        }
                        0b10 => {
                            let res = self.get_reg(rs as u32) + rn as u32;
                            self.set_reg(rd as u32, res);
                        }
                        0b11 => {
                            let res = self.get_reg(rs as u32) - rn as u32;
                            self.set_reg(rd as u32, res);
                        }
                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            }

            return;
        } else if instruction >> 12 & 0b1111 == 0b0101 && instruction >> 9 & 0b1 == 0 {
            // Format VII
            let opcode = instruction >> 10 & 0b11;

            let ro = instruction >> 6 & 0b111;
            let rb = instruction >> 3 & 0b111;
            let rd = instruction & 0b11;

            match opcode {
                0b00 => {
                    let address = self.get_reg(rb as u32) + self.get_reg(ro as u32);
                    let value = self.get_reg(rd as u32);
                    self.interconnect.store32(address, value);
                }
                0b01 => {
                    let address = self.get_reg(rb as u32) + self.get_reg(ro as u32);
                    let value = self.get_reg(rd as u32) as u8;
                    self.interconnect.store8(address, value);
                }
                0b10 => {
                    let address = self.get_reg(rb as u32) + self.get_reg(ro as u32);
                    let res = self.interconnect.load32(address);

                    self.set_reg(rd as u32, res);
                }
                0b11 => {
                    let addr = self.get_reg(rb as u32) + self.get_reg(ro as u32);
                    let res = self.interconnect.load8(addr);
                    self.set_reg(rd as u32, res as u32);
                }
                _ => unreachable!(),
            }

            return;
        } else if instruction >> 12 & 0b1111 == 0b0101 && instruction >> 9 & 0b1 == 1 {
            // Format VIII
            let opcode = instruction >> 10 & 0b11;

            let ro = instruction >> 6 & 0b111;
            let rb = instruction >> 3 & 0b111;
            let rd = instruction & 0b11;

            match opcode {
                0b00 => {
                    let address = self.get_reg(rb as u32) + self.get_reg(ro as u32);
                    let value = self.get_reg(rd as u32) as u16;
                    self.interconnect.store16(address, value);
                }
                0b01 => {
                    let addr = self.get_reg(rb as u32) + self.get_reg(ro as u32);
                    let res = self.interconnect.load8(addr);
                    self.set_reg(rd as u32, res as u32);
                }
                0b10 => {
                    let addr = self.get_reg(rb as u32) + self.get_reg(ro as u32);
                    let res = self.interconnect.load16(addr) as i32;
                    self.set_reg(rd as u32, res as u32);
                }
                0b11 => {
                    let addr = self.get_reg(rb as u32) + self.get_reg(ro as u32);
                    let res = self.interconnect.load16(addr) as i32;
                    self.set_reg(rd as u32, res as u32);
                }
                _ => unreachable!(),
            }
            return;
        } else if instruction >> 13 & 0b111 == 0b001 {
            // Format III
            let opcode = instruction >> 11 & 0b11;

            let rd = instruction >> 8 & 0b111;
            let nn = instruction & 0x7;

            match opcode {
                0b00 => {
                    let res = nn;
                    self.set_reg(rd as u32, res as u32);
                }
                0b01 => {
                    let res = self.get_reg(rd as u32) - nn as u32;
                    //self.set_reg(rd as u32, res);
                    println!("unimplimented yet {}", res);
                }
                0b10 => {
                    let res = self.get_reg(rd as u32) + nn as u32;
                    self.set_reg(rd as u32, res);
                }
                0b11 => {
                    let res = self.get_reg(rd as u32) - nn as u32;
                    self.set_reg(rd as u32, res);
                }
                _ => unreachable!(),
            }

            return;
        } else if instruction >> 12 & 0xf == 0b1001 {
            // Format XI
            let opcode = instruction >> 11 & 0b1;

            let rd = instruction >> 8 & 0b111;
            let nn = (instruction & 0x7) as u32;

            let sp = self.sp;

            match opcode {
                0b0 => {
                    let addr = sp + nn;
                    let value = self.get_reg(rd as u32);
                    self.interconnect.store32(addr, value);
                }
                0b1 => {
                    let addr = sp + nn;
                    let value = self.interconnect.load32(addr);
                    self.set_reg(rd as u32, value);
                }
                _ => unreachable!(),
            }

            return;
        } else if instruction >> 12 & 0xf == 0b1010 {
            // Format XII
            let opcode = instruction >> 11 & 0b1;

            let rd = instruction >> 8 & 0b111;
            let nn = instruction & 0x7;

            match opcode {
                0b0 => {
                    let res = (4 & !2) + nn;
                    self.set_reg(rd as u32, res as u32);
                }
                0b1 => {
                    let res = self.sp + nn as u32;
                    self.set_reg(rd as u32, res);
                }
                _ => unreachable!(),
            }

            return;
        } else if instruction >> 12 & 0xf == 0b1011 {
            // Format XIV
            let opcode = instruction >> 11 & 0b1;

            match opcode {
                0 => {
                    println!("Unimplemented PUSH logic");
                    self.sp -= 1;
                }
                1 => {
                    println!("Unimplemented PULL logic");
                    self.sp += 1;
                }
                _ => unreachable!(),
            }

            let check_point = instruction >> 9 & 0b11;

            if check_point != 0b10 {
                panic!("Incorrect instruction type {:b}", check_point);
            }

            let lr = instruction >> 8 & 0b1;

            match lr {
                0 => (),
                1 => println!("Unimplemented PUSH/PULL logic"),
                _ => unreachable!(),
            }

            return;
        } else if instruction >> 12 & 0xf == 0b1100 {
            // Format XV
            let opcode = instruction >> 11 & 0b1;

            let rb = instruction >> 8 & 0b111;

            let rlist = instruction & 0xff;

            match opcode {
                0 => {
                    println!("Unimplemented STMIA logic");
                    self.sp -= 1;
                }
                1 => {
                    println!("Unimplemented LDMIA logic");
                    self.sp += 1;
                }
                _ => unreachable!(),
            }

            return;
        } else if instruction >> 12 & 0xf == 0b1101 {
            // Format XVI
            let opcode = instruction >> 8 & 0xf;

            match opcode {
                0x0 => {
                    self.cpsr.Z = true;
                }
                0x1 => {
                    self.cpsr.Z = false;
                }
                0x2 => {
                    self.cpsr.C = true;
                }
                0x3 => {
                    self.cpsr.C = false;
                }
                0x4 => {
                    self.cpsr.N = true;
                }
                0x5 => {
                    self.cpsr.N = false;
                }
                0x6 => {
                    self.cpsr.V = true;
                }
                0x7 => {
                    self.cpsr.V = false;
                }
                0x8 => {
                    self.cpsr.C = true;
                    self.cpsr.Z = false;
                }
                0x9 => {
                    self.cpsr.C = false;
                    self.cpsr.Z = true;
                }
                0xA => {
                    self.cpsr.N = self.cpsr.V;
                }
                0xB => {
                    self.cpsr.N = !self.cpsr.V;
                }
                0xC => {
                    self.cpsr.Z = false;
                    self.cpsr.N = self.cpsr.V;
                }
                0xD => {
                    self.cpsr.Z = true;
                    self.cpsr.N = !self.cpsr.V;
                }
                0xE => {
                    unreachable!();
                }
                0xF => {
                    println!("Unimplemented SWI instruction");
                    unimplemented!();
                }
                _ => unreachable!(),
            }

            let check_point = instruction >> 9 & 0b11;

            if check_point != 0b10 {
                panic!("Incorrect instruction type {:b}", check_point);
            }

            let lr = instruction >> 8 & 0b1;

            match lr {
                0 => (),
                1 => println!("Unimplemented PUSH/PULL logic"),
                _ => unreachable!(),
            }

            return;
        } else if instruction >> 11 & 0x1f == 0b11100 {
            // Format XVIII
            let nn = instruction & 0x7ff;

            self.pc = (nn as i32) as u32;

            return;
        } else if instruction >> 11 & 0x1f == 0x1f {
            // Format XIX Part: II
            let opcode = instruction >> 11 & 0x1f;

            let nn = instruction & 0x7ff;

            self.pc = self.current_pc.wrapping_add(4).wrapping_sub(0x400000).wrapping_add(0x3FFFFF);

            return;
        }

        panic!("Unknown instruction 16bit: {:016b}", instruction)
    }

    fn op_and(&mut self, rd: u32, rn: u32, operand2: u32) {
        let rn = self.get_reg(rn);

        let res = rn & operand2;

        self.set_reg(rd, res);
    }

    fn op_eor(&mut self, rd: u32, rn: u32, operand2: u32) {
        let rn = self.get_reg(rn);

        let res = rn ^ operand2;

        self.set_reg(rd, res);
    }

    fn op_sub(&mut self, rd: u32, rn: u32, operand2: u32) {
        let rn = self.get_reg(rn);

        let res = rn.wrapping_sub(operand2);

        self.set_reg(rd, res);
    }

    fn op_rsb(&mut self, rd: u32, rn: u32, operand2: u32) {
        let rn = self.get_reg(rn);

        let res = operand2.wrapping_sub(rn);

        self.set_reg(rd, res);
    }

    fn op_add(&mut self, rd: u32, rn: u32, operand2: u32) {
        let rn = self.get_reg(rn);

        let res = rn.wrapping_add(operand2);

        self.set_reg(rd, res);
    }

    fn op_adc(&mut self, rd: u32, rn: u32, operand2: u32) {
        let rn = self.get_reg(rn);

        let res = rn.wrapping_add(operand2).wrapping_add(self.cpsr.C as u32);

        self.set_reg(rd, res);
    }

    fn op_sbc(&mut self, rd: u32, rn: u32, operand2: u32) {
        let rn = self.get_reg(rn);

        let res = rn.wrapping_sub(operand2).wrapping_add(self.cpsr.C as u32).wrapping_sub(1);

        self.set_reg(rd, res);
    }

    fn op_rsc(&mut self, rd: u32, rn: u32, operand2: u32) {
        let rn = self.get_reg(rn);

        let res = operand2.wrapping_sub(rn).wrapping_add(self.cpsr.C as u32).wrapping_sub(1);

        self.set_reg(rd, res);
    }

    fn op_tst(&mut self, rn: u32, operand2: u32) {
        let res = rn & operand2;
        self.cpsr.N = (res >> 31 & 0b1) == 1;
        self.cpsr.Z = (res >> 30 & 0b1) == 1;
    }

    fn op_teq(&mut self, rn: u32, operand2: u32) {
        let res = rn ^ operand2;
        self.cpsr.N = (res >> 31 & 0b1) == 1;
        self.cpsr.Z = (res >> 30 & 0b1) == 1;
    }

    fn op_cmp(&mut self, rn: u32, operand2: u32) {
        let res = rn.wrapping_sub(operand2);
        self.cpsr.N = (res >> 31 & 0b1) == 1;
        self.cpsr.Z = (res >> 30 & 0b1) == 1;
    }

    fn op_cmn(&mut self, rn: u32, operand2: u32) {
        let res = rn.wrapping_add(operand2);
        self.cpsr.N = (res >> 31 & 0b1) == 1;
        self.cpsr.Z = (res >> 30 & 0b1) == 1;
    }

    fn op_orr(&mut self, rd: u32, rn: u32, operand2: u32) {
        let rn = self.get_reg(rn);

        let res = operand2 | rn;

        self.set_reg(rd, res);
    }

    fn op_mov(&mut self, rd: u32, operand2: u32) {
        self.set_reg(rd, operand2);
    }

    fn op_bic(&mut self, rd: u32, rn: u32, operand2: u32) {
        let rn = self.get_reg(rn);

        let res = rn & !operand2;

        self.set_reg(rd, res);
    }

    fn op_mvn(&mut self, rd: u32, operand2: u32) {
        let res = !operand2;

        self.set_reg(rd, res);
    }
}

enum CpuMode {
  User = 0b10000,
  FIQ = 0b10001,
  IRQ = 0b10010,
  Supervisor = 0b10011,
  Abort = 0b10111,
  Undef = 0b11011,
  System = 0b11111,
}

enum ExceptionVectors {
  Reset = 0x00000000,                 // Supervisor.
  Undefined_instruction = 0x00000004, // Undef.
  Software_interupt = 0x00000008,     // Supervisor.
  Abort_prefitch = 0x0000000C,        // Abort.
  Abort_data = 0x00000010,            // Abort.
  Reserved = 0x00000014,              // Reserved.
  IRQ = 0x00000018,                   // IRQ.
  FIQ = 0x0000001C,                   // FIQ.
}
