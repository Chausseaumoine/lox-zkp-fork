pub mod r#trait;
pub mod schnorr;
//  pub mod or;

pub use r#trait::{SigmaProtocol, AndProof, OrProof};
pub use schnorr::LokZkpSchnorr;