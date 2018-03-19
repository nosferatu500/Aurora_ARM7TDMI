use std::env::args;

mod bios;
mod cpu;
mod interconnect;
mod rom;
mod eram;
mod iram;

use bios::Bios;
use cpu::Cpu;
use interconnect::Interconnect;
use rom::Rom;

fn main() {
    let bios_file = args().nth(1).unwrap();

    let rom_file = args().nth(2).unwrap();

    let bios = Bios::new(&bios_file).unwrap();

    let rom = Rom::new(&rom_file).unwrap();

    let inter = Interconnect::new(bios, rom);

    let mut cpu = Cpu::new(inter);

    cpu.reset();

    let mut i = 0;
    loop {
        println!("#{}", i);
        cpu.run_next_instruction();
        i += 1;
    }
}
