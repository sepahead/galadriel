//! Fixed-size exact accumulation for bounded binary64 detector arithmetic.

// Every finite binary64 value is an integer multiple of 2^-1074. The largest
// finite value occupies bits through position 2097 in those units. A maximum NIS
// window contains 2^16 terms, so 34 limbs (2176 bits) retain its exact real sum,
// including carries, without allocation.
const EXACT_SUM_LIMBS: usize = 34;
const FRACTION_BITS: u32 = 52;
const MAX_FINITE_HIGH_BIT: usize = 2_097;
const MAX_FINITE_SHIFT: usize = 2_045;
const BINARY64_SIGNIFICAND_BITS: usize = 53;
const MAX_SIGNIFICAND: u64 = (1_u64 << BINARY64_SIGNIFICAND_BITS) - 1;

#[derive(Clone, Copy, Debug)]
pub(crate) struct ExactMagnitude([u64; EXACT_SUM_LIMBS]);

impl Default for ExactMagnitude {
    fn default() -> Self {
        Self([0; EXACT_SUM_LIMBS])
    }
}

impl ExactMagnitude {
    pub(crate) fn add_finite(&mut self, value: f64) {
        debug_assert!(value.is_finite() && value >= 0.0);
        let bits = value.to_bits();
        let exponent = ((bits >> FRACTION_BITS) & 0x7ff) as usize;
        let fraction = bits & ((1_u64 << FRACTION_BITS) - 1);
        let (significand, shift) = if exponent == 0 {
            (fraction, 0)
        } else {
            // The hidden bit and stored fraction are disjoint; arithmetic addition
            // makes that canonical composition explicit.
            ((1_u64 << FRACTION_BITS) + fraction, exponent - 1)
        };
        if significand == 0 {
            return;
        }

        let limb = shift / u64::BITS as usize;
        let offset = shift % u64::BITS as usize;
        self.add_word(limb, significand << offset);
        if offset != 0 {
            self.add_word(limb + 1, significand >> (u64::BITS as usize - offset));
        }
    }

    pub(crate) fn subtract_finite(&mut self, value: f64) {
        let mut term = Self::default();
        term.add_finite(value);
        *self = self.subtract(&term);
    }

    fn add_word(&mut self, mut index: usize, mut word: u64) {
        while word != 0 {
            debug_assert!(index < EXACT_SUM_LIMBS);
            let (sum, carry) = self.0[index].overflowing_add(word);
            self.0[index] = sum;
            word = u64::from(carry);
            index += 1;
        }
    }

    pub(crate) fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for index in (0..EXACT_SUM_LIMBS).rev() {
            match self.0[index].cmp(&other.0[index]) {
                std::cmp::Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        std::cmp::Ordering::Equal
    }

    pub(crate) fn subtract(&self, other: &Self) -> Self {
        debug_assert!(self.cmp(other) != std::cmp::Ordering::Less);
        let mut result = Self::default();
        let mut borrow = false;
        for index in 0..EXACT_SUM_LIMBS {
            let (without_other, first_borrow) = self.0[index].overflowing_sub(other.0[index]);
            let (difference, second_borrow) = without_other.overflowing_sub(u64::from(borrow));
            result.0[index] = difference;
            borrow = first_borrow || second_borrow;
        }
        debug_assert!(!borrow);
        result
    }

    fn highest_bit(&self) -> Option<usize> {
        self.0.iter().enumerate().rev().find_map(|(index, &limb)| {
            (limb != 0).then(|| {
                index * u64::BITS as usize + (u64::BITS - 1 - limb.leading_zeros()) as usize
            })
        })
    }

    fn bit(&self, index: usize) -> bool {
        (self.0[index / u64::BITS as usize] >> (index % u64::BITS as usize)) & 1 == 1
    }

    fn any_bits_below(&self, bit_count: usize) -> bool {
        let complete_limbs = bit_count / u64::BITS as usize;
        if self.0[..complete_limbs].iter().any(|&limb| limb != 0) {
            return true;
        }
        let remainder = bit_count % u64::BITS as usize;
        remainder != 0 && self.0[complete_limbs] & ((1_u64 << remainder) - 1) != 0
    }

    fn extract_significand(&self, shift: usize) -> u64 {
        let limb = shift / u64::BITS as usize;
        let offset = shift % u64::BITS as usize;
        let mut value = self.0[limb] >> offset;
        if offset != 0 && limb + 1 < EXACT_SUM_LIMBS {
            value |= self.0[limb + 1] << (u64::BITS as usize - offset);
        }
        value & MAX_SIGNIFICAND
    }

    fn exceeds_f64_max_at(&self, highest_bit: usize) -> bool {
        match highest_bit.cmp(&MAX_FINITE_HIGH_BIT) {
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Equal => {}
        }
        let significand = self.extract_significand(MAX_FINITE_SHIFT);
        significand == MAX_SIGNIFICAND && self.any_bits_below(MAX_FINITE_SHIFT)
    }

    pub(crate) fn exceeds_f64_max(&self) -> bool {
        self.highest_bit()
            .is_some_and(|highest_bit| self.exceeds_f64_max_at(highest_bit))
    }

    /// Round the exact non-negative magnitude to nearest-even binary64, saturating
    /// when the exact real value is outside the finite binary64 range.
    pub(crate) fn saturating_f64(&self) -> f64 {
        let Some(mut highest_bit) = self.highest_bit() else {
            return 0.0;
        };
        if self.exceeds_f64_max_at(highest_bit) {
            return f64::MAX;
        }
        let Some(shift) = highest_bit.checked_sub(FRACTION_BITS as usize) else {
            return f64::from_bits(self.0[0]);
        };

        let mut significand = self.extract_significand(shift);
        if shift != 0 {
            let round_bit = self.bit(shift - 1);
            let sticky = self.any_bits_below(shift - 1);
            if round_bit && (sticky || significand & 1 == 1) {
                significand += 1;
            }
        }
        if significand == 1_u64 << BINARY64_SIGNIFICAND_BITS {
            significand >>= 1;
            highest_bit += 1;
        }

        let exponent = (highest_bit - 51) as u64;
        debug_assert!((1..=2_046).contains(&exponent));
        let fraction = significand - (1_u64 << FRACTION_BITS);
        // The exponent field and stored fraction occupy disjoint bit ranges.
        f64::from_bits((exponent << FRACTION_BITS) + fraction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_sum(values: &[f64]) -> ExactMagnitude {
        let mut sum = ExactMagnitude::default();
        for &value in values {
            sum.add_finite(value);
        }
        sum
    }

    #[test]
    fn preserves_subnormal_units_and_the_normal_boundary() {
        let smallest = f64::from_bits(1);
        assert_eq!(
            exact_sum(&[smallest, smallest]).saturating_f64(),
            f64::from_bits(2)
        );
        assert_eq!(
            exact_sum(&[f64::from_bits((1_u64 << 52) - 1), smallest]).saturating_f64(),
            f64::MIN_POSITIVE
        );
    }

    #[test]
    fn rounds_halfway_cases_to_even() {
        let half_ulp_at_one = 2.0_f64.powi(-53);
        assert_eq!(exact_sum(&[1.0, half_ulp_at_one]).saturating_f64(), 1.0);
        assert_eq!(
            exact_sum(&[1.0 + f64::EPSILON, half_ulp_at_one]).saturating_f64(),
            1.0 + 2.0 * f64::EPSILON
        );
        assert_eq!(
            exact_sum(&[f64::from_bits(2.0_f64.to_bits() - 1), half_ulp_at_one]).saturating_f64(),
            2.0
        );
    }

    #[test]
    fn subtraction_preserves_a_tiny_residual_after_large_cancellation() {
        let smallest = f64::from_bits(1);
        let positive = exact_sum(&[f64::MAX, smallest]);
        let negative = exact_sum(&[f64::MAX]);
        assert_eq!(positive.subtract(&negative).saturating_f64(), smallest);
    }

    #[test]
    fn distinguishes_the_finite_boundary_from_exact_overflow() {
        let maximum = exact_sum(&[f64::MAX]);
        assert!(!maximum.exceeds_f64_max());
        assert_eq!(maximum.saturating_f64(), f64::MAX);

        let overflow = exact_sum(&[f64::MAX, f64::from_bits(1)]);
        assert!(overflow.exceeds_f64_max());
        assert_eq!(overflow.saturating_f64(), f64::MAX);
    }

    #[test]
    fn partial_limb_queries_use_the_exact_remainder() {
        let mut limbs = [0_u64; EXACT_SUM_LIMBS];
        limbs[1] = 0b10;
        let magnitude = ExactMagnitude(limbs);

        assert!(!magnitude.any_bits_below(65));
        assert!(magnitude.any_bits_below(66));
    }

    #[test]
    fn significand_extraction_crosses_only_into_the_immediate_next_limb() {
        let mut limbs = [0_u64; EXACT_SUM_LIMBS];
        limbs[2] = 1_u64 << 63;
        limbs[3] = 0b101;
        let magnitude = ExactMagnitude(limbs);

        assert_eq!(
            magnitude.extract_significand(2 * u64::BITS as usize + 63),
            0b1011
        );

        let mut final_limb = [0_u64; EXACT_SUM_LIMBS];
        final_limb[EXACT_SUM_LIMBS - 1] = 0b110;
        let final_magnitude = ExactMagnitude(final_limb);
        assert_eq!(
            final_magnitude.extract_significand((EXACT_SUM_LIMBS - 1) * u64::BITS as usize + 1),
            0b11
        );
    }
}
