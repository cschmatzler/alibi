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
//! <https://www.sqlite.org/copyright.html>
//! <https://sqlite.org/src/file/src/util.c?ci=version-3.53.2>
//! <https://sqlite.org/src/file/src/printf.c?ci=version-3.53.2>

#![expect(
    clippy::indexing_slicing,
    reason = "finite IEEE754 exponent bounds keep power tables in range; normalized decimal mantissas have 17-18 ASCII digits before guarded shortening"
)]

use std::fmt::Write;
const BASE: [u64; 27] = [
    0x8000_0000_0000_0000,
    0xa000_0000_0000_0000,
    0xc800_0000_0000_0000,
    0xfa00_0000_0000_0000,
    0x9c40_0000_0000_0000,
    0xc350_0000_0000_0000,
    0xf424_0000_0000_0000,
    0x9896_8000_0000_0000,
    0xbebc_2000_0000_0000,
    0xee6b_2800_0000_0000,
    0x9502_f900_0000_0000,
    0xba43_b740_0000_0000,
    0xe8d4_a510_0000_0000,
    0x9184_e72a_0000_0000,
    0xb5e6_20f4_8000_0000,
    0xe35f_a931_a000_0000,
    0x8e1b_c9bf_0400_0000,
    0xb1a2_bc2e_c500_0000,
    0xde0b_6b3a_7640_0000,
    0x8ac7_2304_89e8_0000,
    0xad78_ebc5_ac62_0000,
    0xd8d7_26b7_177a_8000,
    0x8786_7832_6eac_9000,
    0xa968_163f_0a57_b400,
    0xd3c2_1bce_cced_a100,
    0x8459_5161_4014_84a0,
    0xa56f_a5b9_9019_a5c8,
];
const SCALE: [u64; 26] = [
    0x8049_a4ac_0c58_11ae,
    0xcf42_894a_5dce_35ea,
    0xa76c_5823_38ed_2621,
    0x873e_4f75_e222_4e68,
    0xda7f_5bf5_9096_6848,
    0xb080_392c_c434_9dec,
    0x8e93_8662_882a_f53e,
    0xe658_29b3_046b_0afa,
    0xba12_1a46_50e4_ddeb,
    0x964e_858c_91ba_2655,
    0xf2d5_6790_ab41_c2a2,
    0xc428_d05a_a475_1e4c,
    0x9e74_d1b7_91e0_7e48,
    0xcccc_cccc_cccc_cccc,
    0xcecb_8f27_f420_0f3a,
    0xa70c_3c40_a64e_6c51,
    0x86f0_ac99_b4e8_dafd,
    0xda01_ee64_1a70_8de9,
    0xb01a_e745_b101_e9e4,
    0x8e41_ade9_fbeb_c27d,
    0xe5d3_ef28_2a24_2e81,
    0xb9a7_4a06_37ce_2ee1,
    0x95f8_3d0a_1fb6_9cd9,
    0xf24a_01a7_3cf2_dccf,
    0xc3b8_3581_09e8_4f07,
    0x9e19_db92_b4e3_1ba9,
];
const SCALE_LOW: [u32; 26] = [
    0x205b_896d,
    0x5206_4cad,
    0xaf2a_f2b8,
    0x5a77_44a7,
    0xaf39_a475,
    0xbd8d_794e,
    0x547e_b47b,
    0x0cb4_a5a3,
    0x92f3_4d62,
    0x3a6a_07f9,
    0xfae2_7299,
    0xaa97_e14c,
    0x775e_a265,
    0xcccc_cccc,
    0x0000_0000,
    0x9990_90b6,
    0x69a0_28bb,
    0xe80e_6f48,
    0x5ec0_5dd0,
    0x1458_8f14,
    0x8f16_68c9,
    0x6d95_3e2c,
    0x4abd_af10,
    0xbc63_3b39,
    0x0a86_2f81,
    0x6c07_a2c2,
];
// Keep the high 96 bits of the same 160-bit product as SQLite.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "This SQLite numeric port deliberately extracts fixed-width words and preserves upstream IEEE754 rounding"
)]
fn multiply160(a: u64, alo: u32, b: u64) -> (u64, u32) {
    let r = (u128::from(a) * u128::from(b)).wrapping_add((u128::from(alo) * u128::from(b)) >> 32);
    ((r >> 64) as u64, (r >> 32) as u32)
}
// Normalized high 96 bits of 10^p, with the implicit binary exponent.
#[expect(
    clippy::as_conversions,
    clippy::cast_sign_loss,
    reason = "This SQLite numeric port deliberately extracts fixed-width words and preserves upstream IEEE754 rounding"
)]
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
const fn power_10_to_2(p: i32) -> i32 {
    (p * 108_853) >> 15
}
const fn power_2_to_10(p: i32) -> i32 {
    (p * 78913) >> 18
}
// Extract the 18-digit decimal mantissa used before the final 17-digit round.
#[expect(
    clippy::as_conversions,
    reason = "This SQLite numeric port deliberately extracts fixed-width words and preserves upstream IEEE754 rounding"
)]
fn binary_to_decimal(m: u64, e: i32) -> (u64, i32) {
    let p = 17 - power_2_to_10(e + 63);
    let h = ((u128::from(m) * u128::from(power_ten(p).0)) >> 64) as u64;
    let h = h >> (-(e + power_10_to_2(p) + 2));
    (u64::midpoint(h, (h << 1) & 2), -p)
}
// SQLite tests whether shorter trailing-zero/nine forms recover the same f64.
// Its reverse conversion uses round-to-even with a sticky discarded bit.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "This SQLite numeric port deliberately extracts fixed-width words and preserves upstream IEEE754 rounding"
)]
#[expect(
    clippy::many_single_char_names,
    reason = "Retain variable names from the SQLite decimal conversion algorithm for source comparison"
)]
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
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "This SQLite numeric port deliberately extracts fixed-width words and preserves upstream IEEE754 rounding"
)]
#[expect(
    clippy::string_slice,
    reason = "Normalized decimal mantissas contain ASCII digits and each shortening index is bounded by their length"
)]
#[expect(
    clippy::too_many_lines,
    reason = "Keep the SQLite decimal conversion port aligned with its upstream algorithm"
)]
#[expect(
    clippy::many_single_char_names,
    reason = "Retain variable names from the SQLite decimal conversion algorithm for source comparison"
)]
pub(super) fn real_text(input: f64) -> String {
    debug_assert!(
        input.is_finite(),
        "SQLite REAL text conversion requires a finite value"
    );
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
            if r.to_bits() == decimal_to_binary(v2, exp + n as i32 - jj as i32).to_bits() {
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
            if r.to_bits() == decimal_to_binary(v2, exp + n as i32 - jj as i32).to_bits() {
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
        _ = write!(out, "{:02}", exponent.unsigned_abs());
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
