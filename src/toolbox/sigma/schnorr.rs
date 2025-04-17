use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use rand::{Rng, CryptoRng};
use crate::toolbox::sigma::SigmaProtocol;

pub struct LokZkpSchnorr {
    pub generator: RistrettoPoint,
    pub target: RistrettoPoint
}

impl<'a> SigmaProtocol for LokZkpSchnorr {
    type Witness = Scalar;
    type Commitment = RistrettoPoint;
    type ProverState = (Scalar, Scalar);
    type Response = Scalar;

    fn prover_commit(
        &self,
        witness: &Self::Witness,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (Self::Commitment, Self::ProverState) {
        let r = Scalar::random(rng);
        let R = r * self.generator;
        (R, (r, *witness))
    }

    fn prover_response(
            &self,
            state: &Self::ProverState,
            challenge: &Scalar,
        ) -> Self::Response {
        let (r,x) = *state ;
        challenge * x + r
    }

    fn verifier(
            &self,
            commitment: &Self::Commitment,
            challenge: &Scalar,
            response: &Self::Response,
        ) -> bool {
        response * self.generator == challenge * self.target + commitment
    }

    fn simulate_proof(
            &self, 
            challenge: &Scalar,
            rng: &mut (impl Rng + CryptoRng)
        ) -> (Self::Commitment, Self::Response) {
        let z = Scalar::random(rng);
        let R = z * self.generator - challenge * self.target;
        (R,z)
    }
}