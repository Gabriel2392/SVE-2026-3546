pub(super) struct ReedSolomon {
    roots: usize,
    table: Vec<u8>,
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
        let mut table = vec![0; 256 * roots];
        for x in 1..256 {
            for k in 0..roots {
                table[x * roots + k] = alpha[(index[x] as usize + generator[roots - 1 - k] as usize) % 255];
            }
        }
        Self { roots, table }
    }

    pub(super) fn encode(&self, input: &[u8], parity: &mut [u8]) {
        let roots = self.roots;
        if roots == 2 {
            for (&byte, pair) in input.iter().zip(parity.chunks_exact_mut(2)) {
                let x = (byte ^ pair[0]) as usize * 2;
                pair[0] = pair[1] ^ self.table[x]; pair[1] = self.table[x + 1];
            }
            return
        }
        for (&byte, row) in input.iter().zip(parity.chunks_exact_mut(roots)) {
            let x = (byte ^ row[0]) as usize * roots;
            let t = &self.table[x..x + roots];
            for k in 0..roots - 1 { row[k] = row[k + 1] ^ t[k]; }
            row[roots - 1] = t[roots - 1];
        }
    }
}
