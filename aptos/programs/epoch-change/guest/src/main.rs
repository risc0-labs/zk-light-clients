// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use aptos_lc_core::crypto::hash::CryptoHash;
use aptos_lc_core::types::trusted_state::{EpochChangeProof, TrustedState, TrustedStateChange};

use risc0_zkvm::guest::env;

pub fn main() {
    env::log("cycle-tracker-start: read_inputs");

    let trusted_state_bytes = env::read_frame();
    let epoch_change_proof = env::read_frame();

    env::log("cycle-tracker-end: read_inputs");

    // Deserialize Rust structures

    env::log("cycle-tracker-start: deserialize_trusted_state");

    let trusted_state = TrustedState::from_bytes(&trusted_state_bytes)
        .expect("TrustedState::from_bytes: could not create trusted state");

    env::log("cycle-tracker-end: deserialize_trusted_state");

    env::log("cycle-tracker-start: deserialize_epoch_change_proof");

    let epoch_change_proof = EpochChangeProof::from_bytes(&epoch_change_proof)
        .expect("EpochChangeProof::from_bytes: could not create epoch change proof");

    env::log("cycle-tracker-end: deserialize_epoch_change_proof");

    // Verify and ratchet the trusted state

    env::log("cycle-tracker-start: verify_and_ratchet");

    let trusted_state_change = trusted_state
        .verify_and_ratchet_inner(&epoch_change_proof)
        .expect("TrustedState::verify_and_ratchet_inner: could not ratchet");

    env::log("cycle-tracker-end: verify_and_ratchet");

    // Extract new trusted state

    env::log("cycle-tracker-start: validator_verifier_hash");

    let validator_verifier_hash = match trusted_state_change {
        TrustedStateChange::Epoch {
            latest_epoch_change_li,
            ..
        } => latest_epoch_change_li
            .ledger_info()
            .next_epoch_state()
            .expect("Expected epoch state")
            .verifier()
            .hash(),
        _ => panic!("Expected epoch change"),
    };

    env::log("cycle-tracker-end: validator_verifier_hash");

    // Compute previous epoch validator verifier hash and commit it

    env::log("cycle-tracker-start: hash_prev_validator");

    let prev_epoch_validator_verifier_hash = match &trusted_state {
        TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().hash(),
        _ => panic!("Expected epoch change for current trusted state"),
    };
    env::commit_slice(prev_epoch_validator_verifier_hash.as_ref());

    env::log("cycle-tracker-end: hash_prev_validator");

    // Hash new validator verifier and pass the hash as the now trusted state
    env::commit_slice(validator_verifier_hash.as_ref());
}
