// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

use aptos_lc_core::crypto::hash::{CryptoHash, HashValue};
use aptos_lc_core::merkle::sparse_proof::SparseMerkleProof;
use aptos_lc_core::merkle::transaction_proof::TransactionAccumulatorProof;
use aptos_lc_core::types::ledger_info::LedgerInfoWithSignatures;
use aptos_lc_core::types::transaction::TransactionInfo;
use aptos_lc_core::types::validator::ValidatorVerifier;

use risc0_zkvm::guest::env;

fn main() {
    env::log("cycle-tracker-start: read_inputs");

    // Get inputs for account inclusion
    let sparse_merkle_proof_bytes = env::read_frame();
    let key: [u8; 32] = env::read();
    let leaf_value_hash: [u8; 32] = env::read();

    // Get inputs for tx inclusion
    let transaction_bytes = env::read_frame();
    let transaction_index: u64 = env::read();
    let transaction_proof = env::read_frame();
    let ledger_info_bytes = env::read_frame();

    // Latest verified validator verifier &  hash
    let verified_validator_verifier = env::read_frame();

    env::log("cycle-tracker-end: read_inputs");

    // Deserialize Validator Verifier
    let validator_verifier = ValidatorVerifier::from_bytes(&verified_validator_verifier)
        .expect("validator_verifier: could not create ValidatorVerifier from bytes");

    // Verify transaction inclusion in the LedgerInfoWithSignatures
    let transaction = TransactionInfo::from_bytes(&transaction_bytes)
        .expect("from_bytes: could not deserialize TransactionInfo");
    let transaction_hash = transaction.hash();
    let transaction_proof = TransactionAccumulatorProof::from_bytes(&transaction_proof)
        .expect("from_bytes: could not deserialize TransactionAccumulatorProof");
    let latest_li = LedgerInfoWithSignatures::from_bytes(&ledger_info_bytes)
        .expect("from_bytes: could not deserialize LedgerInfo");

    env::log("cycle-tracker-start: verify_transaction_inclusion");

    let expected_root_hash = latest_li.ledger_info().transaction_accumulator_hash();

    transaction_proof
        .verify(expected_root_hash, transaction_hash, transaction_index)
        .expect("verify: could not verify proof");

    env::log("cycle-tracker-end: verify_transaction_inclusion");

    // Check signature

    env::log("cycle-tracker-start: verify_signature");

    latest_li
        .verify_signatures(&validator_verifier)
        .expect("verify_signatures: could not verify signatures");

    env::log("cycle-tracker-end: verify_signature");

    // Verify account inclusion in the SparseMerkleTree
    let sparse_merkle_proof = SparseMerkleProof::from_bytes(&sparse_merkle_proof_bytes)
        .expect("from_bytes: could not deserialize SparseMerkleProof");

    env::log("cycle-tracker-start: verify_merkle_proof");

    let sparse_expected_root_hash = transaction
        .state_checkpoint()
        .expect("state_checkpoint: could not get state checkpoint");
    let reconstructed_root_hash = sparse_merkle_proof
        .verify_by_hash(
            sparse_expected_root_hash,
            HashValue::from_slice(key).expect("key: could not use input to create HashValue"),
            HashValue::from_slice(leaf_value_hash)
                .expect("leaf_value_hash: could not use input to create HashValue"),
        )
        .expect("verify_by_hash: could not verify proof");

    env::log("cycle-tracker-end: verify_merkle_proof");

    // Commit the validator verifier hash
    env::commit_slice(validator_verifier.hash().as_ref());

    // Commit the state root hash
    env::commit_slice(reconstructed_root_hash.as_ref());

    // Commit current block id
    let block_hash = latest_li.ledger_info().block_id();
    env::commit_slice(block_hash.as_ref());

    // Commit key
    env::commit_slice(&key);

    // Commit leaf value hash
    env::commit_slice(&leaf_value_hash);
}
