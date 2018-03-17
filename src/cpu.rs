use interconnect::Interconnect;

struct StatusRegister {
    pub Z: bool,
    pub C: bool,
    pub N: bool,
    pub V: bool,
}

impl StatusRegister {
    pub fn new() -> StatusRegister {
        StatusRegister {
            Z: false,
            C: false,
            N: false,
            V: false,
        }
    }
}

pub struct Cpu {
    pc: u32,
    regs: [u32; 16],

    current_pc: u32,

    interconnect: Interconnect,

    sp: u32,

    lr: u32,

    cpsr: StatusRegister,
}

impl Cpu {
    pub fn new(interconnect: Interconnect) -> Cpu {
        let pc = 15;
        Cpu {
            pc,
            regs: [0xdeadbeef; 16],

            current_pc: pc,

            interconnect,

            sp: 0,

            lr: 0,

            cpsr: StatusRegister::new(),
        }
    }

    pub fn reset(&mut self) {
      let pc = 15 as usize;
      self.regs[pc] = 0xdeadbeef;
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

        if instruction & 1 == CpuMode::THUMB as u32 {
            self.pc = pc.wrapping_add(2);
            self.decode16(instruction as u16);
        } else {
            self.pc = pc.wrapping_add(4);
            self.decode32(instruction);
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

        let res = rn - operand2;

        self.set_reg(rd, res);
    }

    fn op_rsb(&mut self, rd: u32, rn: u32, operand2: u32) {
        let rn = self.get_reg(rn);

        let res = operand2 - rn;

        self.set_reg(rd, res);
    }

    fn op_add(&mut self, rd: u32, rn: u32, operand2: u32) {
        let rn = self.get_reg(rn);

        let res = rn + operand2;

        self.set_reg(rd, res);
    }

    fn op_adc(&mut self, rd: u32, rn: u32, operand2: u32) {
        let rn = self.get_reg(rn);

        let res = rn + operand2 + self.cpsr.C as u32;

        self.set_reg(rd, res);
    }

    fn op_sbc(&mut self, rd: u32, rn: u32, operand2: u32) {
        let rn = self.get_reg(rn);

        let res = rn - operand2 + self.cpsr.C as u32 - 1;

        self.set_reg(rd, res);
    }

    fn op_rsc(&mut self, rd: u32, rn: u32, operand2: u32) {
        let rn = self.get_reg(rn);

        let res = operand2 - rn + self.cpsr.C as u32 - 1;

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
        let res = rn - operand2;
        self.cpsr.N = (res >> 31 & 0b1) == 1;
        self.cpsr.Z = (res >> 30 & 0b1) == 1;
    }

    fn op_cmn(&mut self, rn: u32, operand2: u32) {
        let res = rn + operand2;
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
    THUMB = 1,
    ARM = 0,
}
