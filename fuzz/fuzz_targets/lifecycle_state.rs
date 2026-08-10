#![no_main]
#![forbid(unsafe_code)]

use galadriel_fuzz::exercise_lifecycle_state;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = exercise_lifecycle_state(data);
});
