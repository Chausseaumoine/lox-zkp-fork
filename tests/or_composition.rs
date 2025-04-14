// -*- coding: utf-8; mode: rust; -*-
//
// To the extent possible under law, the authors have waived all
// copyright and related or neighboring rights to zkp,
// using the Creative Commons "CC0" public domain dedication.  See
// <http://creativecommons.org/publicdomain/zero/1.0/> for full
// details.
//
// Authors:
// - Henry de Valence <hdevalence@hdevalence.ca>
#![allow(non_snake_case)]

extern crate bincode;
extern crate curve25519_dalek;
extern crate lox_zkp;
extern crate serde;
extern crate sha2;

use self::sha2::Sha512;

use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use lox_zkp::toolbox::{
    batch_verifier::BatchVerifier, prover::Prover, verifier::Verifier, SchnorrCS,
};
use rand::{thread_rng, Rng, RngCore};

fn or_dleq(x: Scalar, H: RistrettoPoint, B: RistrettoPoint, rng: &mut impl Rng) -> bool {
    // Generation of the real statement using the witness
    let G = B * x;

    // Simulation of the unknown witness
    let s_1 = Scalar::from(rng.next_u64()); // Generate a random answer
    let c_1 = Scalar::from(rng.next_u64()); // Generate a random challenge
    let T_1 = (B * s_1) + (H * -c_1); // Compute the "cheated" commitment for the simulation

    // Commitment of the real witness
    let t_0 = Scalar::from(rng.next_u64());
    let T_0 = B * t_0;

    // Generation of the commitment for the challenge with Fiat-Shamir using T_0 (concat with x would be nice but idk how to do it yet)
    let c = Scalar::hash_from_bytes::<Sha512>(T_0.compress().as_bytes());

    // Generate challenge and answer for the true witness of the OR Proof
    let c_0 = c + c_1;
    let s_0 = c_0 * x + t_0;

    // Verifier checks the correctness of the proof
    let c_check = c_0 - c; // Retrieve commitments
    if ((c_0 * G + T_0).eq(&(s_0 * B))) && ((c_check * H + T_1).eq(&(s_1 * B))) {
        return true   
    }
    false
}

#[test]
fn create_and_verify_compact_or_dleq() {
    let mut rng = thread_rng();
    let x = Scalar::from(89327492234u64); // This is the witness known by the Prover
    let B = dalek_constants::RISTRETTO_BASEPOINT_POINT; // Base point of the curve
    // Generate a random point on the curve, its generator h can be forgotten by the client (in real life deployment h is unknown and H is generated directly)
    let h = Scalar::from(rng.next_u64());
    let H = B * h; 
    
    assert!(or_dleq(x, H, B, &mut rng));

    // Verify that the proof works for any other base point on the curve
    let B = RistrettoPoint::hash_from_bytes::<Sha512>(Scalar::from(111111111u64).as_bytes()); // Random point on the curve
    // Generate a random point on the curve, its generator h can be forgotten by the client (in real life deployment h is unknown and H is generated directly)
    let h = Scalar::from(rng.next_u64());
    let H = B * h; 
    
    assert!(or_dleq(x, H, B, &mut rng));
}