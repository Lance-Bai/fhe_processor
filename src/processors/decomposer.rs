use dyn_stack::{DynArray, PodStack};
use jemalloc_ctl::opt::zero;
use pulp::Scalar;
use std::iter::Map;
use std::ptr::eq;
use std::slice::IterMut;
use tfhe::core_crypto::fft_impl::fft64::math::decomposition::TensorSignedDecompositionLendingIter;
use tfhe::{
    boolean::prelude::{DecompositionBaseLog, DecompositionLevelCount},
    core_crypto::{commons::math::decomposition::DecompositionLevel, prelude::UnsignedInteger},
};

pub struct TensorSignedDecompositionLendingIterLocal<'buffers, Scalar: UnsignedInteger> {
    // The base log of the decomposition
    pub base_log: usize,
    // The current level
    pub current_level: usize,
    // A mask which allows to compute the mod B of a value. For B=2^4, this guy is of the form:
    // ...0001111
    mod_b_mask: Scalar,
    // The internal states of each decomposition
    states: DynArray<'buffers, Scalar>,
    // A flag which stores whether the iterator is a fresh one (for the recompose method).
    fresh: bool,
}

impl<'buffers, Scalar: UnsignedInteger>
    TensorSignedDecompositionLendingIterLocal<'buffers, Scalar>
{
    #[inline]
    pub fn new(
        input: impl Iterator<Item = Scalar>,
        base_log: DecompositionBaseLog,
        level: DecompositionLevelCount,
        stack: PodStack<'buffers>,
    ) -> (Self, PodStack<'buffers>) {
        let shift = Scalar::BITS - base_log.0 * level.0;
        let (states, stack) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, input.map(|i| i >> shift));
        (
            TensorSignedDecompositionLendingIterLocal {
                base_log: base_log.0,
                current_level: level.0,
                mod_b_mask: (Scalar::ONE << base_log.0) - Scalar::ONE,
                states,
                fresh: true,
            },
            stack,
        )
    }

    // inlining this improves perf of external product by about 25%, even in LTO builds
    #[inline]
    pub fn next_term<'short>(
        &'short mut self,
    ) -> Option<(
        DecompositionLevel,
        DecompositionBaseLog,
        Map<IterMut<'short, Scalar>, impl FnMut(&'short mut Scalar) -> Scalar>,
    )> {
        // The iterator is not fresh anymore.
        self.fresh = false;
        // We check if the decomposition is over
        if self.current_level == 0 {
            return None;
        }
        let current_level = self.current_level;
        let base_log = self.base_log;
        let mod_b_mask = self.mod_b_mask;
        self.current_level -= 1;

        Some((
            DecompositionLevel(current_level),
            DecompositionBaseLog(self.base_log),
            self.states
                .iter_mut()
                .map(move |state| decompose_one_level(base_log, state, mod_b_mask)),
        ))
    }
}

#[inline]
pub fn decompose_one_level<S: UnsignedInteger>(base_log: usize, state: &mut S, mod_b_mask: S) -> S {
    let res = *state & mod_b_mask;
    *state >>= base_log;
    let mut carry = (res.wrapping_sub(S::ONE) | *state) & res;
    carry >>= base_log - 1;
    *state += carry;
    res.wrapping_sub(carry << base_log)
}

pub struct LeadOneDecompositionLendingIterLocal<'buffers, Scalar: UnsignedInteger> {
    // The base log of the decomposition
    pub base_log: usize,
    // The current level
    pub current_level: usize,
    // A mask which allows to compute the mod B of a value. For B=2^4, this guy is of the form:
    // ...0001111
    mod_b_mask: Scalar,
    // The internal states of each decomposition
    states: DynArray<'buffers, Scalar>,
    // A flag which stores whether the iterator is a fresh one (for the recompose method).
    fresh: bool,
}

impl<'buffers, Scalar: UnsignedInteger> LeadOneDecompositionLendingIterLocal<'buffers, Scalar> {
    #[inline]
    pub fn new(
        input: impl Iterator<Item = Scalar>,
        base_log: DecompositionBaseLog,
        level: DecompositionLevelCount,
        stack: PodStack<'buffers>,
    ) -> (Self, PodStack<'buffers>) {
        let shift = Scalar::BITS - base_log.0 * (level.0 - 1) - 1;
        let (states, stack) =
            stack.collect_aligned(aligned_vec::CACHELINE_ALIGN, input.map(|i| i >> shift));
        (
            LeadOneDecompositionLendingIterLocal {
                base_log: base_log.0,
                current_level: level.0,
                mod_b_mask: (Scalar::ONE << base_log.0) - Scalar::ONE,
                states,
                fresh: true,
            },
            stack,
        )
    }

    // inlining this improves perf of external product by about 25%, even in LTO builds
    #[inline]
    pub fn next_term<'short>(
        &'short mut self,
    ) -> Option<(
        DecompositionLevel,
        DecompositionBaseLog,
        Map<IterMut<'short, Scalar>, impl FnMut(&'short mut Scalar) -> Scalar>,
    )> {
        // The iterator is not fresh anymore.
        self.fresh = false;
        let current_level = self.current_level;
        let mut base_log = self.base_log;
        let mut mod_b_mask = self.mod_b_mask;

        // We check if the decomposition is over
        if current_level == 0 {
            println!("decomposition over");
            return None;
        } else if current_level == 1 {
            // we are at the last level, we need to output the lead one decomposition of the state
            base_log = 1_usize;
            mod_b_mask = Scalar::ONE;
        }
        // println!("current_level = {}, base_log = {}, mod_b_mask = {:?}", current_level, base_log, mod_b_mask);
        self.current_level -= 1;
        Some((
            DecompositionLevel(current_level),
            DecompositionBaseLog(base_log),
            self.states
                .iter_mut()
                .map(move |state| decompose_one_level(base_log, state, mod_b_mask)),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dyn_stack::{GlobalPodBuffer, StackReq};

    #[test]
    fn test_lead_one_next_term_basic_flow() {
        let input = vec![0b1_110_010u64 << 57, 0b1_010_111u64 << 57];
        let base_log = DecompositionBaseLog(3);
        let level = DecompositionLevelCount(3);

        let req = StackReq::new_aligned::<u64>(64, aligned_vec::CACHELINE_ALIGN);
        let mut mem = GlobalPodBuffer::new(req);
        let stack = PodStack::new(&mut mem);

        let (mut iter, _) =
            LeadOneDecompositionLendingIterLocal::new(input.into_iter(), base_log, level, stack);

        {
            let (decomp_level, decomp_base_log, terms) = iter.next_term().expect("term 1 expected");
            assert_eq!(decomp_level.0, 3);
            assert_eq!(decomp_base_log.0, 3);
            let terms = terms.collect::<Vec<_>>();
            println!("L{} (base_log={}):", decomp_level.0, decomp_base_log.0);
            for (idx, value) in terms.iter().enumerate() {
                println!("  term[{idx}] = {:064b}", value);
            }
        }

        {
            let (decomp_level, decomp_base_log, terms) = iter.next_term().expect("term 2 expected");
            assert_eq!(decomp_level.0, 2);
            assert_eq!(decomp_base_log.0, 3);
            let terms = terms.collect::<Vec<_>>();
            println!("L{} (base_log={}):", decomp_level.0, decomp_base_log.0);
            for (idx, value) in terms.iter().enumerate() {
                println!("  term[{idx}] = {:064b}", value);
            }
        }

        {
            let (decomp_level, decomp_base_log, terms) = iter.next_term().expect("term 3 expected");
            assert_eq!(decomp_level.0, 1);
            assert_eq!(decomp_base_log.0, 1);
            let terms = terms.collect::<Vec<_>>();
            println!("L{} (base_log={}):", decomp_level.0, decomp_base_log.0);
            for (idx, value) in terms.iter().enumerate() {
                println!("  term[{idx}] = {:064b}", value);
            }
        }

        assert!(iter.next_term().is_none());
    }
}
