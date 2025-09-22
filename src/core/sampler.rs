use crate::types::*;
use rand::{Rng, rng};
use std::collections::HashSet;
use tracing::{debug, info};

pub struct RandomSampler {
    matrix_size: u32,
    samples_needed: usize,
}

impl RandomSampler {
    pub fn new(matrix_size: u32, samples_needed: usize) -> Self {
        Self {
            matrix_size,
            samples_needed,
        }
    }

    pub fn generate_coordinates(&self) -> Vec<Coordinate> {
        let mut rng = rng();
        let mut coord = HashSet::new();

        while coord.len() < self.samples_needed {
            coord.insert(Coordinate {
                row: rng.random_range(0..self.matrix_size),
                col: rng.random_range(0..self.matrix_size),
            });
        }
        let result: Vec<_> = coord.into_iter().collect();
        debug!("Generated {} unique coordinates", result.len());
        result
    }

    pub fn calculate_confidence(&self, successful_samples: usize, erasure_rate: f64) -> f64 {
        if successful_samples == 0 {
            return 0.0;
        }
        let detection_threshold = 1.0 - erasure_rate;
        1.0 - detection_threshold.powi(successful_samples as i32)
    }
}
