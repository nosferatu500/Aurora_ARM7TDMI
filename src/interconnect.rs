use bios::Bios;
use rom::Rom;
use iram::IRam;
use eram::ERam;

mod map {
    pub struct Range(u32, u32);

    impl Range {
        pub fn contains(self, addr: u32) -> Option<u32> {
            let Range(start, length) = self;

            if addr >= start && addr < start + length {
                Some(addr - start)
            } else {
                None
            }
        }
    }

    pub const BIOS: Range = Range(0x00000000, 16 * 1024);
    pub const ROM: Range = Range(0x08000000, 32 * 1024);
    pub const E_RAM: Range = Range(0x02000000, 256 * 1024);
    pub const I_RAM: Range = Range(0x03000000, 32 * 1024);
}

pub struct Interconnect {
    bios: Bios,
    rom: Rom,
    iram: IRam,
    eram: ERam,
}

impl Interconnect {
    pub fn new(bios: Bios, rom: Rom) -> Interconnect {
        Interconnect {
            bios,
            rom,
            iram: IRam::new(),
            eram: ERam::new(),
        }
    }

    pub fn load8(&self, addr: u32) -> u8 {
        if let Some(offset) = map::BIOS.contains(addr) {
            return self.bios.load8(offset);
        }

        if let Some(offset) = map::ROM.contains(addr) {
            return self.rom.load8(offset);
        }

        if let Some(offset) = map::E_RAM.contains(addr) {
            return self.eram.load8(offset);
        }

        if let Some(offset) = map::I_RAM.contains(addr) {
            return self.iram.load8(offset);
        }

        panic!("Unhandled load 8bit address {:08x}", addr);
    }

    pub fn load16(&self, addr: u32) -> u16 {
        if let Some(offset) = map::BIOS.contains(addr) {
            return self.bios.load16(offset);
        }

        if let Some(offset) = map::ROM.contains(addr) {
            return self.rom.load16(offset);
        }

        if let Some(offset) = map::E_RAM.contains(addr) {
            return self.eram.load16(offset);
        }

        if let Some(offset) = map::I_RAM.contains(addr) {
            return self.iram.load16(offset);
        }

        panic!("Unhandled load 16bit address {:08x}", addr);
    }

    pub fn load32(&self, addr: u32) -> u32 {
        if let Some(offset) = map::BIOS.contains(addr) {
            return self.bios.load32(offset);
        }

        if let Some(offset) = map::ROM.contains(addr) {
            return self.rom.load32(offset);
        }

        if let Some(offset) = map::E_RAM.contains(addr) {
            return self.eram.load32(offset);
        }

        if let Some(offset) = map::I_RAM.contains(addr) {
            return self.iram.load32(offset);
        }

        panic!("Unhandled load 32bit address {:08x}", addr);
    }

    pub fn store8(&mut self, addr: u32, value: u8) {
        if let Some(offset) = map::E_RAM.contains(addr) {
            self.eram.store8(offset, value);
        }

        if let Some(offset) = map::I_RAM.contains(addr) {
            self.iram.store8(offset, value);
        }

        panic!("Unhandled store 8bit address {:08x}", addr);
    }

    pub fn store16(&mut self, addr: u32, value: u16) {
        if let Some(offset) = map::E_RAM.contains(addr) {
            self.eram.store16(offset, value);
        }

        if let Some(offset) = map::I_RAM.contains(addr) {
            self.iram.store16(offset, value);
        }

        panic!("Unhandled store 16bit address {:08x}", addr);
    }

    pub fn store32(&mut self, addr: u32, value: u32) {
        if let Some(offset) = map::E_RAM.contains(addr) {
            self.eram.store32(offset, value);
        }

        if let Some(offset) = map::I_RAM.contains(addr) {
            self.iram.store32(offset, value);
        }

        panic!("Unhandled store 32bit address {:08x}", addr);
    }
}
