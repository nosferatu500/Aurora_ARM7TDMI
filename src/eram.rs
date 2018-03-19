pub struct ERam {
    data: Vec<u8>,
}

impl ERam {
    pub fn new() -> ERam {
        let data = vec![0; 256 * 1024];

        ERam { data }
    }

    pub fn load8(&self, offset: u32) -> u8 {
        self.data[offset as usize]
    }

    pub fn load16(&self, offset: u32) -> u16 {
        let offset = offset as usize;

        let b0 = self.data[offset + 0] as u16;
        let b1 = self.data[offset + 1] as u16;

        b0 | (b1 << 8)
    }

    pub fn load32(&self, offset: u32) -> u32 {
        let offset = offset as usize;

        let b0 = self.data[offset + 0] as u32;
        let b1 = self.data[offset + 1] as u32;
        let b2 = self.data[offset + 2] as u32;
        let b3 = self.data[offset + 3] as u32;

        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    pub fn store8(&mut self, offset: u32, value: u8) {
        self.data[offset as usize] = value;
    }

    pub fn store16(&mut self, offset: u32, value: u16) {
        let offset = offset as usize;

        let b0 = value as u8;
        let b1 = (value >> 8) as u8;

        self.data[offset + 0] = b0;
        self.data[offset + 1] = b1;
    }

    pub fn store32(&mut self, offset: u32, value: u32) {
        let offset = offset as usize;

        let b0 = value as u8;
        let b1 = (value >> 8) as u8;
        let b2 = (value >> 16) as u8;
        let b3 = (value >> 24) as u8;

        self.data[offset + 0] = b0;
        self.data[offset + 1] = b1;
        self.data[offset + 2] = b2;
        self.data[offset + 3] = b3;
    }
}
