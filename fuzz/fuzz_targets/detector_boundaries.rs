#![no_main]
#![forbid(unsafe_code)]

use galadriel_fuzz::exercise_detector_boundaries;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = exercise_detector_boundaries(data);
});
