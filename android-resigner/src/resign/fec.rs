pub(super) struct ReedSolomon {
    roots: usize,
    alpha: [u8; 256],
    index: [u8; 256],
    generator: Vec<u8>,
}

impl ReedSolomon {
    pub(super) fn new(roots: usize) -> Self {
        let mut alpha = [0; 256]; let mut index = [0; 256]; index[0] = 255;
        let mut value = 1u16;
        for i in 0..255 {
            alpha[i] = value as u8; index[value as usize] = i as u8; value <<= 1;
            if value & 0x100 != 0 { value ^= 0x11d }
        }
        let mut generator = vec![0; roots + 1]; generator[0] = 1;
        for i in 0..roots {
            generator[i + 1] = 1;
            for j in (1..=i).rev() {
                generator[j] = if generator[j] == 0 { generator[j - 1] }
                    else { generator[j - 1] ^ alpha[(index[generator[j] as usize] as usize + i) % 255] };
            }
            generator[0] = alpha[(index[generator[0] as usize] as usize + i) % 255];
        }
        for value in &mut generator { *value = index[*value as usize] }
        Self { roots, alpha, index, generator }
    }

    pub(super) fn update(&self, byte: u8, parity: &mut [u8]) {
        let feedback = self.index[(byte ^ parity[0]) as usize];
        if feedback != 255 {
            for j in 1..self.roots {
                parity[j] ^= self.alpha[(feedback as usize + self.generator[self.roots - j] as usize) % 255];
            }
        }
        parity.copy_within(1..self.roots, 0);
        parity[self.roots - 1] = if feedback == 255 { 0 }
            else { self.alpha[(feedback as usize + self.generator[0] as usize) % 255] };
    }

}
