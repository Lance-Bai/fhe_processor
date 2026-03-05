pub struct PlainTrivium {
    state: [u8; 288],
}

impl PlainTrivium {
    pub fn new(key: Vec<u64>, iv: Vec<u64>) -> Self {
        let mut state = [0u8; 288];

        let key_bits = Self::vec_u64_to_bits(&key, 80);
        let iv_bits = Self::vec_u64_to_bits(&iv, 80);

        // s1..s93
        for i in 0..80 {
            state[i] = key_bits[i];
        }
        for i in 80..93 {
            state[i] = 0;
        }

        // s94..s177
        for i in 0..80 {
            state[93 + i] = iv_bits[i];
        }
        for i in 80..84 {
            state[93 + i] = 0;
        }

        // s178..s288
        for i in 177..285 {
            state[i] = 0;
        }

        state[285] = 1;
        state[286] = 1;
        state[287] = 1;

        let mut trivium = Self { state };

        // warmup 1152 rounds
        // for _ in 0..1152 {
        //     trivium.next_bit();
        // }

        trivium
    }

    fn vec_u64_to_bits(v: &Vec<u64>, bit_len: usize) -> Vec<u8> {
        let mut bits = Vec::with_capacity(bit_len);

        for &word in v {
            for i in 0..64 {
                bits.push(((word >> i) & 1) as u8);
                if bits.len() == bit_len {
                    return bits;
                }
            }
        }

        bits.resize(bit_len, 0);
        bits
    }

    fn next_bit(&mut self) -> u8 {
        let s = &self.state;

        let t1 = s[65] ^ s[92];
        let t2 = s[161] ^ s[176];
        let t3 = s[242] ^ s[287];

        let z = t1 ^ t2 ^ t3;

        let t1n = t1 ^ (s[90] & s[91]) ^ s[170];
        let t2n = t2 ^ (s[174] & s[175]) ^ s[263];
        let t3n = t3 ^ (s[285] & s[286]) ^ s[68];

        // shift
        for i in (1..93).rev() {
            self.state[i] = self.state[i - 1];
        }
        self.state[0] = t3n;

        for i in (94..177).rev() {
            self.state[i] = self.state[i - 1];
        }
        self.state[93] = t1n;

        for i in (178..288).rev() {
            self.state[i] = self.state[i - 1];
        }
        self.state[177] = t2n;

        z
    }

    pub fn gen_bit(&mut self) -> u8 {
        self.next_bit()
    }

    pub fn gen_u64(&mut self) -> u64 {
        let mut x = 0u64;
        for i in 0..64 {
            x |= (self.gen_bit() as u64) << i;
        }
        x
    }
}