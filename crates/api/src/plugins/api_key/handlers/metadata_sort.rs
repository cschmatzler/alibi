// Copyright (C) 2024-2026 Apple Inc. All rights reserved.
// Copyright (C) 2018-2026 the V8 project authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY APPLE INC. ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
// OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Copyright (c) 2001-2018 Python Software Foundation; All Rights Reserved.
// Part of JavaScriptCore's galloping merge comes from Python's TimSort.

//! Fallible JavaScriptCore array ordering for cached metadata. Its relational
//! comparator can be cyclic, so comparison order is observable. Binary
//! insertion, natural runs, Powersort and galloping follow JSC's StableSort.h:
//! https://github.com/WebKit/WebKit/blob/main/Source/JavaScriptCore/runtime/StableSort.h
//! The behavior is verified against the installed, pinned Bun runtime.

use better_auth_core::{ApiKey, AuthError, AuthResult};
use std::slice::SliceIndex;

fn get<I: SliceIndex<[ApiKey]>>(keys: &[ApiKey], index: I) -> AuthResult<&I::Output> {
    keys.get(index)
        .ok_or_else(|| AuthError::internal("Invalid metadata sort range"))
}

fn get_mut<I: SliceIndex<[ApiKey]>>(keys: &mut [ApiKey], index: I) -> AuthResult<&mut I::Output> {
    keys.get_mut(index)
        .ok_or_else(|| AuthError::internal("Invalid metadata sort range"))
}

struct Order {
    descending: bool,
}

impl Order {
    fn less(&self, left: &ApiKey, right: &ApiKey) -> AuthResult<bool> {
        let ordering =
            super::compare_metadata(left.metadata.as_deref(), right.metadata.as_deref())?;
        Ok(if self.descending {
            ordering.is_gt()
        } else {
            ordering.is_lt()
        })
    }
}

fn insertion(keys: &mut [ApiKey], header: usize, order: &Order) -> AuthResult<()> {
    for index in header + 1..keys.len() {
        let mut left = 0;
        let mut right = index;
        while left < right {
            let middle = left + (right - left) / 2;
            if order.less(get(keys, index)?, get(keys, middle)?)? {
                right = middle;
            } else {
                left = middle + 1;
            }
        }
        get_mut(keys, left..=index)?.rotate_right(1);
    }
    Ok(())
}

fn run(keys: &mut [ApiKey], begin: usize, order: &Order) -> AuthResult<usize> {
    let mut end = begin;
    if end + 1 < keys.len() {
        let descending = order.less(get(keys, end + 1)?, get(keys, end)?)?;
        end += 1;
        while end + 1 < keys.len() {
            if order.less(get(keys, end + 1)?, get(keys, end)?)? != descending {
                break;
            }
            end += 1;
        }
        if descending {
            get_mut(keys, begin..=end)?.reverse();
        }
    }
    if end - begin < 8 {
        let size = 64.min(keys.len() - begin);
        insertion(get_mut(keys, begin..begin + size)?, end - begin, order)?;
        end = begin + size - 1;
    }
    while end + 1 < keys.len() && !order.less(get(keys, end + 1)?, get(keys, end)?)? {
        end += 1;
    }
    Ok(end)
}

/// Exponential then binary search, retaining JSC's comparator orientation.
fn gallop(
    key: &ApiKey,
    keys: &[ApiKey],
    hint: usize,
    after_equal: bool,
    order: &Order,
) -> AuthResult<usize> {
    let compare = |target: &ApiKey| {
        if after_equal {
            order.less(key, target)
        } else {
            order.less(target, key)
        }
    };
    let go_left = compare(get(keys, hint)?)? == after_equal;
    let mut last = 0;
    let mut offset = 1;
    let limit = if go_left { hint + 1 } else { keys.len() - hint };
    while offset < limit {
        let index = if go_left {
            hint - offset
        } else {
            hint + offset
        };
        if compare(get(keys, index)?)? == (after_equal != go_left) {
            break;
        }
        last = offset;
        offset = offset.saturating_mul(2).saturating_add(1).min(limit);
    }
    let (mut left, mut right) = if go_left {
        (hint + 1 - offset, hint - last)
    } else {
        (hint + last + 1, hint + offset)
    };
    while left < right {
        let middle = left + (right - left) / 2;
        if compare(get(keys, middle)?)? == after_equal {
            right = middle;
        } else {
            left = middle + 1;
        }
    }
    Ok(right)
}

fn merge(
    keys: &mut [ApiKey],
    working: &mut [ApiKey],
    begin: usize,
    middle: usize,
    end: usize,
    min_gallop: &mut usize,
    order: &Order,
) -> AuthResult<()> {
    let source = get(keys, begin..end)?;
    let destination = get_mut(working, begin..end)?;
    destination.clone_from_slice(source);
    let middle = middle - begin;
    let mut left = gallop(get(source, middle)?, get(source, ..middle)?, 0, true, order)?;
    if left == middle {
        return Ok(());
    }
    let right_end = middle
        + gallop(
            get(source, middle - 1)?,
            get(source, middle..)?,
            source.len() - middle - 1,
            false,
            order,
        )?;
    let mut right = middle;
    let mut output = left;
    'merging: while left < middle && right < right_end {
        let mut left_wins = 0;
        let mut right_wins = 0;
        while left_wins < *min_gallop && right_wins < *min_gallop {
            if left == middle || right == right_end {
                break 'merging;
            }
            let index = if order.less(get(source, right)?, get(source, left)?)? {
                right_wins += 1;
                left_wins = 0;
                let index = right;
                right += 1;
                index
            } else {
                left_wins += 1;
                right_wins = 0;
                let index = left;
                left += 1;
                index
            };
            get_mut(destination, output)?.clone_from(get(source, index)?);
            output += 1;
        }
        *min_gallop += 1;
        loop {
            *min_gallop = min_gallop.saturating_sub(1).max(1);
            if left == middle || right == right_end {
                break 'merging;
            }
            left_wins = gallop(
                get(source, right)?,
                get(source, left..middle)?,
                0,
                true,
                order,
            )?;
            get_mut(destination, output..output + left_wins)?
                .clone_from_slice(get(source, left..left + left_wins)?);
            output += left_wins;
            left += left_wins;
            get_mut(destination, output)?.clone_from(get(source, right)?);
            output += 1;
            right += 1;
            if left == middle || right == right_end {
                break 'merging;
            }
            right_wins = gallop(
                get(source, left)?,
                get(source, right..right_end)?,
                0,
                false,
                order,
            )?;
            get_mut(destination, output..output + right_wins)?
                .clone_from_slice(get(source, right..right + right_wins)?);
            output += right_wins;
            right += right_wins;
            get_mut(destination, output)?.clone_from(get(source, left)?);
            output += 1;
            left += 1;
            if left == middle || right == right_end {
                break 'merging;
            }
            if left_wins < 7 && right_wins < 7 {
                break;
            }
        }
        *min_gallop += 1;
    }
    for index in (left..middle).chain(right..right_end) {
        get_mut(destination, output)?.clone_from(get(source, index)?);
        output += 1;
    }
    get_mut(keys, begin..end)?.clone_from_slice(destination);
    Ok(())
}

pub(super) fn sort(keys: &mut [ApiKey], direction: Option<&str>) -> AuthResult<()> {
    let order = Order {
        descending: direction == Some("desc"),
    };
    if keys.len() < 8 {
        return insertion(keys, 0, &order);
    }
    let mut working = keys.to_vec();
    let mut min_gallop = 7;
    let mut stack: Vec<(usize, u32)> = Vec::new();
    let mut begin = 0;
    let mut end = run(keys, begin, &order)?;
    while end + 1 < keys.len() {
        let next_begin = end + 1;
        let next_end = run(keys, next_begin, &order)?;
        // Scaled adjacent run midpoints determine their Powersort tree depth.
        let first = ((begin as u128 + next_begin as u128) << 62) / keys.len() as u128;
        let second = ((next_begin as u128 + next_end as u128 + 1) << 62) / keys.len() as u128;
        let power = (first ^ second).leading_zeros();
        while stack.last().is_some_and(|(_, previous)| *previous > power) {
            if let Some((previous, _)) = stack.pop() {
                merge(
                    keys,
                    &mut working,
                    previous,
                    begin,
                    end + 1,
                    &mut min_gallop,
                    &order,
                )?;
                begin = previous;
            }
        }
        stack.push((begin, power));
        begin = next_begin;
        end = next_end;
    }
    while let Some((previous, _)) = stack.pop() {
        merge(
            keys,
            &mut working,
            previous,
            begin,
            end + 1,
            &mut min_gallop,
            &order,
        )?;
        begin = previous;
    }
    Ok(())
}
