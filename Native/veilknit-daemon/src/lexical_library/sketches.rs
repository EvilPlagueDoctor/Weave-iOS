//! Small merge-friendly statistical sketches used by the lexical library.
//!
//! The important property is idempotent union: if two librarians saw the same
//! object and later exchange sketches, unioning their evidence does not simply
//! add the observation twice.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HllSketch {
    precision: u8,
    registers: Vec<u8>,
}

impl HllSketch {
    pub fn new(precision: u8) -> Self {
        let precision = precision.clamp(4, 14);
        Self { precision, registers: vec![0; 1usize << precision] }
    }
    pub fn tiny() -> Self { Self::new(4) }
    pub fn word() -> Self { Self::new(6) }
    pub fn universe() -> Self { Self::new(10) }
    pub fn precision(&self) -> u8 { self.precision }
    pub fn registers(&self) -> &[u8] { &self.registers }

    pub fn add_hash(&mut self, hash: u64) {
        let p = self.precision as u32;
        let index_mask = (1u64 << p) - 1;
        let index = (hash & index_mask) as usize;
        let remaining = hash >> p;
        // `remaining` occupies only (64-p) meaningful bits in a u64. Remove
        // the p vacated leading bits before calculating rho().
        let max_rank = (64 - p + 1) as u8;
        let meaningful_leading_zeros = remaining.leading_zeros().saturating_sub(p);
        let rank = (meaningful_leading_zeros + 1).min(max_rank as u32) as u8;
        if rank > self.registers[index] { self.registers[index] = rank; }
    }

    pub fn merge(&mut self, other: &Self) -> bool {
        if self.precision != other.precision || self.registers.len() != other.registers.len() { return false; }
        for (left, right) in self.registers.iter_mut().zip(&other.registers) { *left = (*left).max(*right); }
        true
    }

    pub fn estimate(&self) -> f64 {
        let m = self.registers.len() as f64;
        if m == 0.0 { return 0.0; }
        let alpha = match self.registers.len() {
            16 => 0.673, 32 => 0.697, 64 => 0.709,
            _ => 0.7213 / (1.0 + 1.079 / m),
        };
        let harmonic = self.registers.iter().map(|&r| 2f64.powi(-(r as i32))).sum::<f64>();
        if harmonic == 0.0 { return 0.0; }
        let raw = alpha * m * m / harmonic;
        let zeroes = self.registers.iter().filter(|&&v| v == 0).count() as f64;
        if raw <= 2.5 * m && zeroes > 0.0 { m * (m / zeroes).ln() } else { raw }
    }
}
impl Default for HllSketch { fn default() -> Self { Self::word() } }

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntityFingerprint(pub [u8; 6]);
impl EntityFingerprint { pub fn hex(&self) -> String { hex::encode(self.0) } }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SamplePoint {
    pub entity: EntityFingerprint,
    pub sample_hash: u64,
    pub generation: u64,
    pub mentions: u16,
    pub last_seen_epoch: u64,
    #[serde(default)] pub topic_minhash: Vec<u16>,
    #[serde(default)] pub language_minhash: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct DeterministicSample { pub capacity: u16, pub points: Vec<SamplePoint> }
impl DeterministicSample {
    pub fn with_capacity(capacity: usize) -> Self { Self { capacity: capacity.clamp(1, u16::MAX as usize) as u16, points: Vec::new() } }
    pub fn upsert(&mut self, point: SamplePoint) {
        if self.capacity == 0 { self.capacity = 1; }
        if let Some(existing) = self.points.iter_mut().find(|x| x.entity == point.entity) {
            if point.generation >= existing.generation { *existing = point; }
            else { existing.last_seen_epoch = existing.last_seen_epoch.max(point.last_seen_epoch); }
            return;
        }
        self.points.push(point);
        self.points.sort_by_key(|p| p.sample_hash);
        self.points.truncate(self.capacity as usize);
    }
    pub fn merge(&mut self, other: &Self) { if self.capacity == 0 { self.capacity = other.capacity.max(1); } for p in &other.points { self.upsert(p.clone()); } }
    pub fn prune_before_epoch(&mut self, minimum_epoch: u64) { self.points.retain(|p| p.last_seen_epoch >= minimum_epoch); }
    pub fn mention_statistics(&self, minimum_epoch: u64) -> MentionStatistics {
        let mut values: Vec<u16> = self.points.iter().filter(|p| p.last_seen_epoch >= minimum_epoch && p.mentions > 0).map(|p| p.mentions).collect();
        if values.is_empty() { return MentionStatistics::default(); }
        values.sort_unstable();
        let sum: u64 = values.iter().map(|&v| v as u64).sum();
        let count = values.len();
        let median = if count % 2 == 1 { values[count/2] as f64 } else { (values[count/2-1] as f64 + values[count/2] as f64)/2.0 };
        let p90_index = (((count as f64)*0.90).ceil() as usize).saturating_sub(1).min(count-1);
        MentionStatistics { nonzero_sample_count: count, mean: sum as f64/count as f64, median, p90: values[p90_index] as f64, max: *values.last().unwrap_or(&0) }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq)]
pub struct MentionStatistics { pub nonzero_sample_count: usize, pub mean: f64, pub median: f64, pub p90: f64, pub max: u16 }

pub fn union_hll<'a, I>(precision: u8, sketches: I) -> HllSketch where I: IntoIterator<Item=&'a HllSketch> {
    let mut result = HllSketch::new(precision); for sketch in sketches { let _ = result.merge(sketch); } result
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn hll_union_is_idempotent() { let mut a=HllSketch::word(); for i in 0..1000u64 { a.add_hash(i.wrapping_mul(0x9e3779b97f4a7c15)); } let mut b=a.clone(); let before=b.estimate(); assert!(b.merge(&a)); assert!((before-b.estimate()).abs()<f64::EPSILON); }
    #[test] fn deterministic_samples_deduplicate_entities() { let e=EntityFingerprint([1,2,3,4,5,6]); let mut a=DeterministicSample::with_capacity(4); a.upsert(SamplePoint{entity:e,sample_hash:2,generation:1,mentions:2,last_seen_epoch:1,topic_minhash:vec![],language_minhash:vec![]}); let mut b=DeterministicSample::with_capacity(4); b.upsert(SamplePoint{entity:e,sample_hash:2,generation:2,mentions:3,last_seen_epoch:1,topic_minhash:vec![],language_minhash:vec![]}); a.merge(&b); assert_eq!(a.points.len(),1); assert_eq!(a.points[0].generation,2); }
}
