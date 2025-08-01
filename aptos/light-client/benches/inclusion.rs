// Copyright (c) Argument Computer Corporation
// SPDX-License-Identifier: Apache-2.0

//! # Benchmark Test for Account Inclusion Proving and Verification
//!
//! This benchmark assesses the performance of the Aptos Light Client's account inclusion proof process
//! across different sizes of state trees. It tests both the proving and verification time required for
//! account inclusion using the `ProverClient` from `sphinx_sdk`.
//!
//! The test checks:
//!
//! - Proving and verifying the inclusion of an account in the state tree.
//!
//! Predicates checked during the benchmark:
//! - P1(V, S_h): Validates that the validator verifier hash V is consistent with the previous epoch's validator verifier hash.
//! - P3(A, V, S_h): Validates that an account value V for account A exists in the state tree with Merkle root S_h.
//!
//! The benchmark aims to determine how state tree size impacts the efficiency of the proof generation and verification process.

use anyhow::anyhow;
use aptos_lc::inclusion::{
    SparseMerkleProofAssets, TransactionProofAssets, ValidatorVerifierAssets,
};
use aptos_lc_core::aptos_test_utils::wrapper::AptosWrapper;
use aptos_lc_core::crypto::hash::CryptoHash;
use aptos_lc_core::types::ledger_info::LedgerInfoWithSignatures;
use aptos_lc_core::types::trusted_state::TrustedState;
use aptos_lc_core::types::validator::ValidatorVerifier;
use inclusion_program_builder::{INCLUSION_PROGRAM_ELF, INCLUSION_PROGRAM_ID};
use risc0_zkvm::{BonsaiProver, ExecutorEnv, LocalProver, ProveInfo, Prover, Receipt};
use serde::Serialize;
use std::env;
use std::hint::black_box;
use std::io::{Cursor, Read};
use std::time::Instant;

const NBR_LEAVES: [usize; 5] = [32, 128, 2048, 8192, 32768];
const NBR_VALIDATORS: usize = 130;
const AVERAGE_SIGNERS_NBR: usize = 95;

struct ProvingAssets<P> {
    prover: P,
    sparse_merkle_proof_assets: SparseMerkleProofAssets,
    transaction_proof_assets: TransactionProofAssets,
    validator_verifier_assets: ValidatorVerifierAssets,
    // Final state hash
    state_checkpoint_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProvingMode {
    STARK,
    SNARK,
}

impl From<ProvingMode> for String {
    fn from(mode: ProvingMode) -> String {
        match mode {
            ProvingMode::STARK => "STARK".to_string(),
            ProvingMode::SNARK => "SNARK".to_string(),
        }
    }
}

impl TryFrom<&str> for ProvingMode {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "STARK" => Ok(ProvingMode::STARK),
            "SNARK" => Ok(ProvingMode::SNARK),
            _ => Err(anyhow!("Invalid proving mode")),
        }
    }
}

impl<P: Prover> ProvingAssets<P> {
    fn from_nbr_leaves(prover: P, nbr_leaves: usize) -> Self {
        let mut aptos_wrapper =
            AptosWrapper::new(nbr_leaves, NBR_VALIDATORS, AVERAGE_SIGNERS_NBR).unwrap();
        aptos_wrapper.generate_traffic().unwrap();

        let trusted_state = bcs::to_bytes(aptos_wrapper.trusted_state()).unwrap();
        let validator_verifier = match TrustedState::from_bytes(&trusted_state).unwrap() {
            TrustedState::EpochState { epoch_state, .. } => epoch_state.verifier().clone(),
            _ => panic!("expected epoch state"),
        };

        let proof_assets = aptos_wrapper
            .get_latest_proof_account(nbr_leaves - 1)
            .unwrap();

        let sparse_merkle_proof = bcs::to_bytes(proof_assets.state_proof()).unwrap();
        let key: [u8; 32] = *proof_assets.key().as_ref();
        let element_hash: [u8; 32] = *proof_assets.state_value_hash().unwrap().as_ref();

        let transaction = bcs::to_bytes(&proof_assets.transaction()).unwrap();
        let transaction_proof = bcs::to_bytes(&proof_assets.transaction_proof()).unwrap();
        let latest_li = aptos_wrapper.get_latest_li_bytes().unwrap();

        let sparse_merkle_proof_assets =
            SparseMerkleProofAssets::new(sparse_merkle_proof, key, element_hash);

        let state_checkpoint_hash = proof_assets
            .transaction()
            .ensure_state_checkpoint_hash()
            .unwrap();

        let transaction_proof_assets = TransactionProofAssets::new(
            transaction,
            *proof_assets.transaction_version(),
            transaction_proof,
            latest_li,
        );

        let validator_verifier_assets = ValidatorVerifierAssets::new(validator_verifier.to_bytes());

        Self {
            prover,
            sparse_merkle_proof_assets,
            transaction_proof_assets,
            validator_verifier_assets,
            state_checkpoint_hash: *state_checkpoint_hash.as_ref(),
        }
    }

    /// Proves the account inclusion using the ProverClient.
    /// Evaluates the predicate P3 during the proving process.
    fn prove(&self) -> Result<ProveInfo, anyhow::Error> {
        let env = ExecutorEnv::builder()
            .write_frame(&self.sparse_merkle_proof_assets.sparse_merkle_proof())
            .write(self.sparse_merkle_proof_assets.leaf_key())?
            .write(self.sparse_merkle_proof_assets.leaf_hash())?
            .write_frame(&self.transaction_proof_assets.transaction())
            .write(self.transaction_proof_assets.transaction_index())?
            .write_frame(&self.transaction_proof_assets.transaction_proof())
            .write_frame(&self.transaction_proof_assets.latest_li())
            .write_frame(&self.validator_verifier_assets.validator_verifier())
            .build()?;

        self.prover.prove(env, INCLUSION_PROGRAM_ELF)
    }

    fn verify(&self, receipt: &Receipt) {
        receipt
            .verify(INCLUSION_PROGRAM_ID)
            .expect("Verification failed");
    }
}

fn read_array<const N: usize>(cursor: &mut Cursor<Vec<u8>>) -> std::io::Result<[u8; N]> {
    let mut array = [0u8; N];
    cursor.read_exact(&mut array)?;
    Ok(array)
}

#[derive(Serialize)]
struct Timings {
    nbr_leaves: usize,
    proving_time: u128,
    verifying_time: u128,
    cycles: u64,
}

fn main() {
    let mode_str: String = env::var("MODE").unwrap_or_else(|_| "STARK".into());
    let mode = ProvingMode::try_from(mode_str.as_str()).expect("MODE should be STARK or SNARK");

    for nbr_leaves in NBR_LEAVES {
        let prover = LocalProver::new("epoch_change_prover");
        let proving_assets = ProvingAssets::from_nbr_leaves(prover, nbr_leaves);

        let start_proving = Instant::now();
        let inclusion_proof = proving_assets.prove().expect("Proving failed");
        let proving_time = start_proving.elapsed();

        let mut journal = Cursor::new(inclusion_proof.receipt.journal.bytes.clone());

        // Verify the consistency of the validator verifier hash post-merkle proof.
        // This verifies the validator consistency required by P1.
        let prev_validator_verifier_hash: [u8; 32] =
            read_array(&mut journal).expect("Failed to read previous validator verifier hash");
        assert_eq!(
            &prev_validator_verifier_hash,
            ValidatorVerifier::from_bytes(
                proving_assets
                    .validator_verifier_assets
                    .validator_verifier()
            )
            .unwrap()
            .hash()
            .as_ref()
        );

        // Verify the consistency of the final merkle root hash computed
        // by the program against the expected one.
        // This verifies P3 out-of-circuit.
        let merkle_root_slice: [u8; 32] =
            read_array(&mut journal).expect("Failed to read merkle_root_slice");
        assert_eq!(
            merkle_root_slice, proving_assets.state_checkpoint_hash,
            "Merkle root hash mismatch"
        );

        let block_hash: [u8; 32] = read_array(&mut journal).expect("Failed to read block_hash");
        let lates_li = proving_assets.transaction_proof_assets.latest_li();
        let expected_block_id = LedgerInfoWithSignatures::from_bytes(lates_li)
            .unwrap()
            .ledger_info()
            .block_id();
        assert_eq!(
            block_hash.to_vec(),
            expected_block_id.to_vec(),
            "Block hash mismatch"
        );

        let key: [u8; 32] = read_array(&mut journal).expect("Failed to read key");
        assert_eq!(
            key.to_vec(),
            proving_assets.sparse_merkle_proof_assets.leaf_key(),
            "Merkle tree key mismatch"
        );

        let value: [u8; 32] = read_array(&mut journal).expect("Failed to read value");
        assert_eq!(
            value.to_vec(),
            proving_assets.sparse_merkle_proof_assets.leaf_hash(),
            "Merkle tree value mismatch"
        );

        let start_verifying = Instant::now();
        proving_assets.verify(black_box(&inclusion_proof.receipt));
        let verifying_time = start_verifying.elapsed();

        let timings = Timings {
            nbr_leaves,
            proving_time: proving_time.as_millis(),
            verifying_time: verifying_time.as_millis(),
            cycles: inclusion_proof.stats.total_cycles,
        };

        let json_output = serde_json::to_string(&timings).unwrap();
        println!("{}", json_output);
    }
}
