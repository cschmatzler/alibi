//! SQLite 3.53 REAL-to-TEXT conversion used by the pinned Bun SQLite adapter.
//!
//! SQLite before 3.52 emits fewer significant digits, so its implicit TEXT
//! affinity can change a supplied numeric phone number and uniqueness behavior.
//! This finite-number port preserves the reference adapter's decimal conversion
//! without changing the consumer's SQLite dependency. The caller still binds
//! the supplied numeric value to a real backend CAST and propagates its errors.
//!
//! Ported from SQLite 3.53.2 (source d6e03d8c777cfa2d35e3b60d8ec3e018), src/util.c (powerOfTen, sqlite3Fp2Convert10,
//! sqlite3Fp10Convert2, sqlite3FpDecode) and src/printf.c (%!.17g).
//! SQLite dedicates this source to the public domain:
//! https://www.sqlite.org/copyright.html
//! https://sqlite.org/src/file/src/util.c?ci=version-3.53.2
//! https://sqlite.org/src/file/src/printf.c?ci=version-3.53.2

#![allow(
    clippy::indexing_slicing,
    reason = "finite IEEE754 exponent bounds keep power tables in range; normalized decimal mantissas have 17-18 ASCII digits before guarded shortening"
)]

const BASE: [u64; 27] = [
    0x8000000000000000,
    0xa000000000000000,
    0xc800000000000000,
    0xfa00000000000000,
    0x9c40000000000000,
    0xc350000000000000,
    0xf424000000000000,
    0x9896800000000000,
    0xbebc200000000000,
    0xee6b280000000000,
    0x9502f90000000000,
    0xba43b74000000000,
    0xe8d4a51000000000,
    0x9184e72a00000000,
    0xb5e620f480000000,
    0xe35fa931a0000000,
    0x8e1bc9bf04000000,
    0xb1a2bc2ec5000000,
    0xde0b6b3a76400000,
    0x8ac7230489e80000,
    0xad78ebc5ac620000,
    0xd8d726b7177a8000,
    0x878678326eac9000,
    0xa968163f0a57b400,
    0xd3c21bcecceda100,
    0x84595161401484a0,
    0xa56fa5b99019a5c8,
];
const SCALE: [u64; 26] = [
    0x8049a4ac0c5811ae,
    0xcf42894a5dce35ea,
    0xa76c582338ed2621,
    0x873e4f75e2224e68,
    0xda7f5bf590966848,
    0xb080392cc4349dec,
    0x8e938662882af53e,
    0xe65829b3046b0afa,
    0xba121a4650e4ddeb,
    0x964e858c91ba2655,
    0xf2d56790ab41c2a2,
    0xc428d05aa4751e4c,
    0x9e74d1b791e07e48,
    0xcccccccccccccccc,
    0xcecb8f27f4200f3a,
    0xa70c3c40a64e6c51,
    0x86f0ac99b4e8dafd,
    0xda01ee641a708de9,
    0xb01ae745b101e9e4,
    0x8e41ade9fbebc27d,
    0xe5d3ef282a242e81,
    0xb9a74a0637ce2ee1,
    0x95f83d0a1fb69cd9,
    0xf24a01a73cf2dccf,
    0xc3b8358109e84f07,
    0x9e19db92b4e31ba9,
];
const SCALE_LOW: [u32; 26] = [
    0x205b896d, 0x52064cad, 0xaf2af2b8, 0x5a7744a7, 0xaf39a475, 0xbd8d794e, 0x547eb47b, 0x0cb4a5a3,
    0x92f34d62, 0x3a6a07f9, 0xfae27299, 0xaa97e14c, 0x775ea265, 0xcccccccc, 0x00000000, 0x999090b6,
    0x69a028bb, 0xe80e6f48, 0x5ec05dd0, 0x14588f14, 0x8f1668c9, 0x6d953e2c, 0x4abdaf10, 0xbc633b39,
    0x0a862f81, 0x6c07a2c2,
];
// Keep the high 96 bits of the same 160-bit product as SQLite.
fn multiply160(a: u64, alo: u32, b: u64) -> (u64, u32) {
    let r = (u128::from(a) * u128::from(b)).wrapping_add((u128::from(alo) * u128::from(b)) >> 32);
    ((r >> 64) as u64, (r >> 32) as u32)
}
// Normalized high 96 bits of 10^p, with the implicit binary exponent.
fn power_ten(p: i32) -> (u64, u32) {
    if p == -1 {
        return (SCALE[13], SCALE_LOW[13]);
    }
    if (0..27).contains(&p) {
        return (BASE[p as usize], 0);
    }
    let g = p.div_euclid(27);
    let n = p.rem_euclid(27) as usize;
    let idx = (g + 13) as usize;
    if n == 0 {
        return (SCALE[idx], SCALE_LOW[idx]);
    }
    let (mut x, mut lo) = multiply160(SCALE[idx], SCALE_LOW[idx], BASE[n]);
    if x & (1 << 63) == 0 {
        x = (x << 1) | u64::from(lo >> 31);
        lo = (lo << 1) | 1;
    }
    (x, lo)
}
fn power_10_to_2(p: i32) -> i32 {
    (p * 108853) >> 15
}
fn power_2_to_10(p: i32) -> i32 {
    (p * 78913) >> 18
}
// Extract the 18-digit decimal mantissa used before the final 17-digit round.
fn binary_to_decimal(m: u64, e: i32) -> (u64, i32) {
    let p = 17 - power_2_to_10(e + 63);
    let h = ((u128::from(m) * u128::from(power_ten(p).0)) >> 64) as u64;
    let h = h >> (-(e + power_10_to_2(p) + 2));
    ((h + ((h << 1) & 2)) >> 1, -p)
}
// SQLite tests whether shorter trailing-zero/nine forms recover the same f64.
// Its reverse conversion uses round-to-even with a sticky discarded bit.
fn decimal_to_binary(d: u64, p: i32) -> f64 {
    if p < -348 {
        return 0.0;
    }
    if p > 347 {
        return f64::INFINITY;
    }
    let b = 64 - d.leading_zeros() as i32;
    let lp = power_10_to_2(p);
    let mut e = 53 - b - lp;
    if e > 1074 {
        if e >= 1130 {
            return 0.0;
        }
        e = 1074;
    }
    let s = -(e - (64 - b) + lp + 3);
    let (mut ph, mut pl) = power_ten(p);
    if pl != 0 {
        ph = ph.wrapping_add(1);
        pl = !pl;
    }
    let x = d << (64 - b);
    let r = u128::from(x) * u128::from(ph);
    let mut hi = (r >> 64) as u64;
    let mut lo = r as u64;
    let mid1 = (lo >> 32) as u32;
    let mut sticky = 1_u64;
    if hi & ((1_u64 << s) - 1) == 0 {
        lo = ((u128::from(x) * u128::from(u64::from(pl) << 32)) >> 64) as u64;
        let mid2 = (lo >> 32) as u32;
        sticky = u64::from(mid1.wrapping_sub(mid2) > 1);
        hi = hi.wrapping_sub(u64::from(mid1 < mid2));
    }
    let mut u = (hi >> s) | sticky;
    let adj = i32::from(u >= (1_u64 << 55) - 2);
    if adj != 0 {
        u = (u >> adj) | (u & 1);
        e -= adj;
    }
    let mut m = (u + 1 + ((u >> 2) & 1)) >> 2;
    if e <= -972 {
        return f64::INFINITY;
    }
    if m & (1 << 52) != 0 {
        m = (m & !(1 << 52)) | (((1075 - e) as u64) << 52);
    }
    f64::from_bits(m)
}
pub(super) fn real_text(input: f64) -> String {
    debug_assert!(input.is_finite());
    if input == 0.0 {
        return "0.0".to_owned();
    }
    let r = input.abs();
    let bits = r.to_bits();
    let mut e = ((bits >> 52) & 0x7ff) as i32;
    let mut m = bits & 0x000f_ffff_ffff_ffff;
    if e == 0 {
        let shift = m.leading_zeros();
        m <<= shift;
        e = -1074 - shift as i32;
    } else {
        m = (m << 11) | (1 << 63);
        e -= 1086;
    }
    let (d, exp) = binary_to_decimal(m, e);
    let mut digits = d.to_string().into_bytes();
    let n = digits.len();
    let mut dp = n as i32 + exp;
    let mut round = 17;
    if n > round {
        if digits[15] == b'9' && digits[14] == b'9' {
            let mut jj = 14;
            while jj > 0 && digits[jj - 1] == b'9' {
                jj -= 1;
            }
            let v2 = if jj == 0 {
                1
            } else {
                digits[..jj]
                    .iter()
                    .fold(0_u64, |value, digit| value * 10 + u64::from(digit - b'0'))
                    + 1
            };
            if r == decimal_to_binary(v2, exp + n as i32 - jj as i32) {
                round = jj + 1;
            }
        } else if dp >= n as i32 || (digits[15] == b'0' && digits[14] == b'0' && digits[13] == b'0')
        {
            let mut jj = 13;
            while digits[jj - 1] == b'0' {
                jj -= 1;
            }
            let v2 = digits[..jj]
                .iter()
                .fold(0_u64, |value, digit| value * 10 + u64::from(digit - b'0'));
            if r == decimal_to_binary(v2, exp + n as i32 - jj as i32) {
                round = jj + 1;
            }
        }
        if digits[round] >= b'5' {
            let mut pos = round - 1;
            loop {
                digits[pos] += 1;
                if digits[pos] <= b'9' {
                    break;
                }
                digits[pos] = b'0';
                if pos == 0 {
                    digits.insert(0, b'1');
                    round += 1;
                    dp += 1;
                    break;
                }
                pos -= 1;
            }
        }
        digits.truncate(round);
    }
    while digits.last() == Some(&b'0') {
        _ = digits.pop();
    }
    let text: String = digits.into_iter().map(char::from).collect();
    let mut out = if input < 0.0 {
        "-".to_owned()
    } else {
        String::new()
    };
    let exponent = dp - 1;
    if !(-4..17).contains(&exponent) {
        out.push_str(&text[..1]);
        out.push('.');
        out.push_str(if text.len() == 1 { "0" } else { &text[1..] });
        out.push('e');
        out.push(if exponent < 0 { '-' } else { '+' });
        out.push_str(&format!("{:02}", exponent.unsigned_abs()));
    } else if dp <= 0 {
        out.push_str("0.");
        out.push_str(&"0".repeat((-dp) as usize));
        out.push_str(&text);
    } else if dp as usize >= text.len() {
        out.push_str(&text);
        out.push_str(&"0".repeat(dp as usize - text.len()));
        out.push_str(".0");
    } else {
        out.push_str(&text[..dp as usize]);
        out.push('.');
        out.push_str(&text[dp as usize..]);
    }
    out
}
