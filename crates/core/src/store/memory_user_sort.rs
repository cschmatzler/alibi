// Copyright (c) 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
// 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018 Python Software Foundation;
// All Rights Reserved. See memory_user_sort.LICENSE.
//
// Rust index-only adaptation of Node v26.13.0's
// deps/v8/third_party/v8/builtins/array-sort.tq:486-1270,1418-1430.
// VM element access is omitted. Comparison order, run merging and galloping
// are retained: Better Auth's mixed-ID comparator is not a total order.

use std::cmp::Ordering;

pub(super) fn indices(length: usize, compare: impl Fn(usize, usize) -> Ordering) -> Vec<usize> {
    Sort {
        work: (0..length).collect(),
        runs: Vec::new(),
        min_gallop: 7,
        compare,
    }
    .run()
}

struct Sort<F> {
    work: Vec<usize>,
    runs: Vec<(usize, usize)>,
    min_gallop: usize,
    compare: F,
}

impl<F: Fn(usize, usize) -> Ordering> Sort<F> {
    fn run(mut self) -> Vec<usize> {
        let length = self.work.len();
        if length < 8 {
            self.insertion(0, 0, length);
            return self.work;
        }
        let mut min_run = length;
        let mut remainder = 0;
        while min_run >= 64 {
            remainder |= min_run & 1;
            min_run >>= 1;
        }
        min_run += remainder;
        let mut base = 0;
        while base < length {
            let mut count = self.count_run(base);
            if count < min_run {
                let forced = min_run.min(length - base);
                self.insertion(base, base + count, base + forced);
                count = forced;
            }
            self.runs.push((base, count));
            self.collapse();
            base += count;
        }
        while self.runs.len() > 1 {
            let mut at = self.runs.len() - 2;
            if at > 0 && self.runs[at - 1].1 < self.runs[at + 1].1 {
                at -= 1;
            }
            self.merge(at);
        }
        self.work
    }

    fn count_run(&mut self, base: usize) -> usize {
        if base + 1 == self.work.len() {
            return 1;
        }
        let descending = (self.compare)(self.work[base + 1], self.work[base]) == Ordering::Less;
        let mut end = base + 2;
        while end < self.work.len() {
            let order = (self.compare)(self.work[end], self.work[end - 1]);
            if (order == Ordering::Less) != descending {
                break;
            }
            end += 1;
        }
        if descending {
            self.work[base..end].reverse();
        }
        end - base
    }

    fn insertion(&mut self, base: usize, start: usize, end: usize) {
        for at in start.max(base + 1)..end {
            let pivot = self.work[at];
            let (mut left, mut right) = (base, at);
            while left < right {
                let mid = left + (right - left) / 2;
                if (self.compare)(pivot, self.work[mid]) == Ordering::Less {
                    right = mid;
                } else {
                    left = mid + 1;
                }
            }
            self.work.copy_within(left..at, left + 1);
            self.work[left] = pivot;
        }
    }

    fn invariant(&self, at: usize) -> bool {
        at < 2 || self.runs[at - 2].1 > self.runs[at - 1].1 + self.runs[at].1
    }

    fn collapse(&mut self) {
        while self.runs.len() > 1 {
            let mut at = self.runs.len() - 2;
            if !self.invariant(at + 1) || !self.invariant(at) {
                if self.runs[at - 1].1 < self.runs[at + 1].1 {
                    at -= 1;
                }
            } else if self.runs[at].1 > self.runs[at + 1].1 {
                break;
            }
            self.merge(at);
        }
    }

    fn merge(&mut self, at: usize) {
        let (mut base_a, mut length_a) = self.runs[at];
        let (base_b, mut length_b) = self.runs[at + 1];
        self.runs[at].1 += length_b;
        self.runs.remove(at + 1);
        let skip = gallop(
            &self.work,
            self.work[base_b],
            base_a,
            length_a,
            0,
            true,
            &self.compare,
        );
        base_a += skip;
        length_a -= skip;
        if length_a == 0 {
            return;
        }
        length_b = gallop(
            &self.work,
            self.work[base_a + length_a - 1],
            base_b,
            length_b,
            length_b - 1,
            false,
            &self.compare,
        );
        if length_b == 0 {
            return;
        }
        if length_a <= length_b {
            self.merge_low(base_a, length_a, base_b, length_b);
        } else {
            self.merge_high(base_a, length_a, base_b, length_b);
        }
    }

    fn merge_low(
        &mut self,
        base_a: usize,
        mut length_a: usize,
        base_b: usize,
        mut length_b: usize,
    ) {
        let temp = self.work[base_a..base_a + length_a].to_vec();
        let (mut dest, mut a, mut b) = (base_a, 0, base_b);
        self.work[dest] = self.work[b];
        dest += 1;
        b += 1;
        length_b -= 1;
        let mut min_gallop = self.min_gallop;
        'merge: {
            if length_b == 0 || length_a == 1 {
                break 'merge;
            }
            loop {
                let (mut wins_a, mut wins_b) = (0, 0);
                loop {
                    if (self.compare)(self.work[b], temp[a]) == Ordering::Less {
                        self.work[dest] = self.work[b];
                        dest += 1;
                        b += 1;
                        wins_b += 1;
                        length_b -= 1;
                        wins_a = 0;
                        if length_b == 0 {
                            break 'merge;
                        }
                        if wins_b >= min_gallop {
                            break;
                        }
                    } else {
                        self.work[dest] = temp[a];
                        dest += 1;
                        a += 1;
                        wins_a += 1;
                        length_a -= 1;
                        wins_b = 0;
                        if length_a == 1 {
                            break 'merge;
                        }
                        if wins_a >= min_gallop {
                            break;
                        }
                    }
                }
                min_gallop += 1;
                let mut first = true;
                while wins_a >= 7 || wins_b >= 7 || first {
                    first = false;
                    min_gallop = min_gallop.saturating_sub(1).max(1);
                    self.min_gallop = min_gallop;
                    wins_a = gallop(&temp, self.work[b], a, length_a, 0, true, &self.compare);
                    if wins_a > 0 {
                        self.work[dest..dest + wins_a].copy_from_slice(&temp[a..a + wins_a]);
                        dest += wins_a;
                        a += wins_a;
                        length_a -= wins_a;
                        if length_a <= 1 {
                            break 'merge;
                        }
                    }
                    self.work[dest] = self.work[b];
                    dest += 1;
                    b += 1;
                    length_b -= 1;
                    if length_b == 0 {
                        break 'merge;
                    }
                    wins_b = gallop(&self.work, temp[a], b, length_b, 0, false, &self.compare);
                    if wins_b > 0 {
                        self.work.copy_within(b..b + wins_b, dest);
                        dest += wins_b;
                        b += wins_b;
                        length_b -= wins_b;
                        if length_b == 0 {
                            break 'merge;
                        }
                    }
                    self.work[dest] = temp[a];
                    dest += 1;
                    a += 1;
                    length_a -= 1;
                    if length_a == 1 {
                        break 'merge;
                    }
                }
                min_gallop += 1;
                self.min_gallop = min_gallop;
            }
        }
        if length_a == 1 && length_b > 0 {
            self.work.copy_within(b..b + length_b, dest);
            self.work[dest + length_b] = temp[a];
        } else if length_a > 0 {
            self.work[dest..dest + length_a].copy_from_slice(&temp[a..a + length_a]);
        }
    }

    fn merge_high(
        &mut self,
        base_a: usize,
        mut length_a: usize,
        base_b: usize,
        mut length_b: usize,
    ) {
        let temp = self.work[base_b..base_b + length_b].to_vec();
        let (mut dest, mut a, mut b) = (base_b + length_b, base_a + length_a, length_b);
        dest -= 1;
        a -= 1;
        self.work[dest] = self.work[a];
        length_a -= 1;
        let mut min_gallop = self.min_gallop;
        'merge: {
            if length_a == 0 || length_b == 1 {
                break 'merge;
            }
            loop {
                let (mut wins_a, mut wins_b) = (0, 0);
                loop {
                    if (self.compare)(temp[b - 1], self.work[a - 1]) == Ordering::Less {
                        dest -= 1;
                        a -= 1;
                        self.work[dest] = self.work[a];
                        wins_a += 1;
                        length_a -= 1;
                        wins_b = 0;
                        if length_a == 0 {
                            break 'merge;
                        }
                        if wins_a >= min_gallop {
                            break;
                        }
                    } else {
                        dest -= 1;
                        b -= 1;
                        self.work[dest] = temp[b];
                        wins_b += 1;
                        length_b -= 1;
                        wins_a = 0;
                        if length_b == 1 {
                            break 'merge;
                        }
                        if wins_b >= min_gallop {
                            break;
                        }
                    }
                }
                min_gallop += 1;
                let mut first = true;
                while wins_a >= 7 || wins_b >= 7 || first {
                    first = false;
                    min_gallop = min_gallop.saturating_sub(1).max(1);
                    self.min_gallop = min_gallop;
                    let k = gallop(
                        &self.work,
                        temp[b - 1],
                        base_a,
                        length_a,
                        length_a - 1,
                        true,
                        &self.compare,
                    );
                    wins_a = length_a - k;
                    if wins_a > 0 {
                        dest -= wins_a;
                        a -= wins_a;
                        self.work.copy_within(a..a + wins_a, dest);
                        length_a -= wins_a;
                        if length_a == 0 {
                            break 'merge;
                        }
                    }
                    dest -= 1;
                    b -= 1;
                    self.work[dest] = temp[b];
                    length_b -= 1;
                    if length_b == 1 {
                        break 'merge;
                    }
                    let k = gallop(
                        &temp,
                        self.work[a - 1],
                        0,
                        length_b,
                        length_b - 1,
                        false,
                        &self.compare,
                    );
                    wins_b = length_b - k;
                    if wins_b > 0 {
                        dest -= wins_b;
                        b -= wins_b;
                        self.work[dest..dest + wins_b].copy_from_slice(&temp[b..b + wins_b]);
                        length_b -= wins_b;
                        if length_b <= 1 {
                            break 'merge;
                        }
                    }
                    dest -= 1;
                    a -= 1;
                    self.work[dest] = self.work[a];
                    length_a -= 1;
                    if length_a == 0 {
                        break 'merge;
                    }
                }
                min_gallop += 1;
                self.min_gallop = min_gallop;
            }
        }
        if length_b == 1 && length_a > 0 {
            dest -= length_a;
            a -= length_a;
            self.work.copy_within(a..a + length_a, dest);
            self.work[dest - 1] = temp[b - 1];
        } else if length_b > 0 {
            self.work[dest - length_b..dest].copy_from_slice(&temp[..length_b]);
        }
    }
}

fn gallop(
    array: &[usize],
    key: usize,
    base: usize,
    length: usize,
    hint: usize,
    right: bool,
    compare: &impl Fn(usize, usize) -> Ordering,
) -> usize {
    let before = |at| {
        if right {
            compare(key, array[base + at]) != Ordering::Less
        } else {
            compare(array[base + at], key) == Ordering::Less
        }
    };
    let (mut last, mut offset) = (0, 1);
    let (mut low, mut high) = if before(hint) {
        let max = length - hint;
        while offset < max && before(hint + offset) {
            last = offset;
            offset = (offset * 2 + 1).min(max);
        }
        offset = offset.min(max);
        (hint + last + 1, hint + offset)
    } else {
        let max = hint + 1;
        while offset < max && !before(hint - offset) {
            last = offset;
            offset = (offset * 2 + 1).min(max);
        }
        offset = offset.min(max);
        (hint + 1 - offset, hint - last)
    };
    while low < high {
        let mid = low + (high - low) / 2;
        if before(mid) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    high
}
