//Note this is just draft implementation of honkVerifier logic over stellar soroban
//We haven't implemented BN254 precompile for now , so use arkwork's bn254 instead
#![no_std]
extern crate alloc;
use wee_alloc::WeeAlloc;

//We keep this allocator as WASM need a memory allocator to handle dynamic memory allocation.
#[global_allocator]
static ALLOC: WeeAlloc = WeeAlloc::INIT;

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G2Affine ,Fq12};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, Zero,One};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use soroban_sdk::{
    contract, contractimpl, crypto, panic_with_error, symbol_short, vec, Bytes,BytesN, Env, Vec, U256,
};

const N: u32 = 131072;
const LOG_N: u32 = 17;
const NUMBER_OF_PUBLIC_INPUTS: u32 = 4;
const CONST_PROOF_SIZE_LOG_N: usize = 28;
const NUMBER_OF_SUBRELATIONS: usize = 26;
const BATCHED_RELATION_PARTIAL_LENGTH: usize = 8;
const NUMBER_OF_ENTITIES: usize = 40;
const NUMBER_UNSHIFTED: usize = 35;
const NUMBER_TO_BE_SHIFTED: usize = 5;
const NUMBER_OF_ALPHAS: usize = 25;

// Error codes
#[derive(Clone, Debug)]
#[repr(u32)]
pub enum Error {
    ProofLengthWrong = 0,
    PublicInputsLengthWrong = 1,
    SumcheckFailed = 2,
    ShpleminiFailed = 3,
    InvalidProof = 4,
}

#[derive(Clone, Debug)]
pub struct G1Point {
    x: Fq, //from ark_bn254
    y: Fq, //from ark_bn254
}

/// Performs checks to ensure that the point is on the curve and is in the right subgroup.
//  pub fn new(x: P::BaseField, y: P::BaseField) -> Self {
//     let point = Self {
//         x,
//         y,
//         infinity: false,
//     };
//     assert!(point.is_on_curve());
//     assert!(point.is_in_correct_subgroup_assuming_on_curve());
//     point
// }
impl G1Point {
    fn to_affine(&self) -> Result<G1Affine, Error> {
        let point = G1Affine::new_unchecked(self.x, self.y);
        if !point.is_on_curve() {
            return Err(Error::InvalidProof);
        }

        if !point.is_in_correct_subgroup_assuming_on_curve() {
            return Err(Error::InvalidProof);
        }
        Ok(point)
    }
}

#[derive(Clone, Debug, Copy)]
pub struct G1ProofPoint {
    x_0: Fq,
    x_1: Fq,
    y_0: Fq,
    y_1: Fq,
}

/*
  Example usage :
    let mut reader = BytesReader::new(&proof_bytes);
    let proof_point = G1ProofPoint::from_reader(&mut reader);
    let g1_point = proof_point.to_g1_point();
*/
impl G1ProofPoint {
    //read proof bytes and turn it into struct G1ProofPoint
    fn from_reader(reader: &mut BytesReader) -> Self {
        Self {
            x_0: reader.read_fq(),
            x_1: reader.read_fq(),
            y_0: reader.read_fq(),
            y_1: reader.read_fq(),
        }
    }

    //convert struct G1ProofPoint to actual G1Point
    fn to_g1_point(&self) -> G1Point {
        let shift = Fq::from(2u128).pow(&[136u64]);
        let x = self.x_0 + self.x_1 * shift;
        let y = self.y_0 + self.y_1 * shift;
        G1Point { x, y }
    }
}

#[derive(Clone, Debug)]
pub struct VerificationKey {
    circuit_size: u32,
    log_circuit_size: u32,
    public_inputs_size: u32,
    q_m: G1Affine,
    q_c: G1Affine,
    q_l: G1Affine,
    q_r: G1Affine,
    q_o: G1Affine,
    q_4: G1Affine,
    q_lookup: G1Affine,
    q_arith: G1Affine,
    q_delta_range: G1Affine,
    q_elliptic: G1Affine,
    q_aux: G1Affine,
    q_poseidon2_external: G1Affine,
    q_poseidon2_internal: G1Affine,
    s1: G1Affine,
    s2: G1Affine,
    s3: G1Affine,
    s4: G1Affine,
    id1: G1Affine,
    id2: G1Affine,
    id3: G1Affine,
    id4: G1Affine,
    t1: G1Affine,
    t2: G1Affine,
    t3: G1Affine,
    t4: G1Affine,
    lagrange_first: G1Affine,
    lagrange_last: G1Affine,
}

//proof
#[derive(Clone, Debug)]
pub struct Proof {
    circuit_size: u32,
    public_inputs_size: u32,
    public_inputs_offset: u32,
    w1: G1ProofPoint,
    w2: G1ProofPoint,
    w3: G1ProofPoint,
    w4: G1ProofPoint,
    z_perm: G1ProofPoint,
    lookup_read_counts: G1ProofPoint,
    lookup_read_tags: G1ProofPoint,
    lookup_inverses: G1ProofPoint,
    sumcheck_univariates: [[Fr; BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N],
    sumcheck_evaluations: [Fr; NUMBER_OF_ENTITIES],
    gemini_fold_comms: [G1ProofPoint; CONST_PROOF_SIZE_LOG_N - 1],
    gemini_a_evaluations: [Fr; CONST_PROOF_SIZE_LOG_N],
    shplonk_q: G1ProofPoint,
    kzg_quotient: G1ProofPoint,
}

struct BytesReader<'a> {
    bytes: &'a [u8],
    pos: usize, //position
}

impl<'a> BytesReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn read_u32(&mut self) -> u32 {
        let mut arr = [0u8; 4];
        arr.copy_from_slice(&self.bytes[self.pos..self.pos + 4]);
        self.pos += 4;
        u32::from_be_bytes(arr)
    }
    fn read_fq(&mut self) -> Fq {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.bytes[self.pos..self.pos + 32]);
        self.pos += 32;
        Fq::from_be_bytes_mod_order(&arr)
    }
    fn read_fr(&mut self) -> Fr {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.bytes[self.pos..self.pos + 32]);
        self.pos += 32;
        Fr::from_be_bytes_mod_order(&arr)
    }
}

impl Proof {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = BytesReader::new(bytes);

        let circuit_size = reader.read_u32();
        let public_inputs_size = reader.read_u32();
        let public_inputs_offset = reader.read_u32();

        let w1 = G1ProofPoint::from_reader(&mut reader);
        let w2 = G1ProofPoint::from_reader(&mut reader);
        let w3 = G1ProofPoint::from_reader(&mut reader);
        let lookup_read_counts = G1ProofPoint::from_reader(&mut reader);
        let lookup_read_tags = G1ProofPoint::from_reader(&mut reader);
        let w4 = G1ProofPoint::from_reader(&mut reader);
        let lookup_inverses = G1ProofPoint::from_reader(&mut reader);
        let z_perm = G1ProofPoint::from_reader(&mut reader);

        // sumcheck_univariates
        let mut sumcheck_univariates =
            [[Fr::zero(); BATCHED_RELATION_PARTIAL_LENGTH]; CONST_PROOF_SIZE_LOG_N];
        for i in 0..CONST_PROOF_SIZE_LOG_N {
            for j in 0..BATCHED_RELATION_PARTIAL_LENGTH {
                sumcheck_univariates[i][j] = reader.read_fr();
            }
        }

        // sumcheck_evaluations
        let mut sumcheck_evaluations = [Fr::zero(); NUMBER_OF_ENTITIES];
        for i in 0..NUMBER_OF_ENTITIES {
            sumcheck_evaluations[i] = reader.read_fr();
        }

        // gemini_fold_comms
        let mut gemini_fold_comms = [G1ProofPoint {
            x_0: Fq::zero(),
            x_1: Fq::zero(),
            y_0: Fq::zero(),
            y_1: Fq::zero(),
        }; CONST_PROOF_SIZE_LOG_N - 1];
        for i in 0..(CONST_PROOF_SIZE_LOG_N - 1) {
            gemini_fold_comms[i] = G1ProofPoint::from_reader(&mut reader);
        }

        // gemini_a_evaluations
        let mut gemini_a_evaluations = [Fr::zero(); CONST_PROOF_SIZE_LOG_N];
        for i in 0..CONST_PROOF_SIZE_LOG_N {
            gemini_a_evaluations[i] = reader.read_fr();
        }

        let shplonk_q = G1ProofPoint::from_reader(&mut reader);
        let kzg_quotient = G1ProofPoint::from_reader(&mut reader);

        Ok(Proof {
            circuit_size,
            public_inputs_size,
            public_inputs_offset,
            w1,
            w2,
            w3,
            w4,
            z_perm,
            lookup_read_counts,
            lookup_read_tags,
            lookup_inverses,
            sumcheck_univariates,
            sumcheck_evaluations,
            gemini_fold_comms,
            gemini_a_evaluations,
            shplonk_q,
            kzg_quotient,
        })
    }
}

pub struct Transcript {
    env: Env,
    buffer: Bytes,
}


impl Transcript {
    pub fn new(env: &Env) -> Self {
        Self {
            env: env.clone(),
            buffer: Bytes::new(env),
        }
    }

    pub fn append_bytes(&mut self, bytes: &[u8]) {
         // Create a Bytes object from the raw slice  
        let bytes_obj = Bytes::from_slice(&self.env, bytes);  
        // Use copy_from_slice or extend_from_slice directly on buffer  
        self.buffer.extend_from_slice(&bytes);
    }

    pub fn append_u32(&mut self, value: u32) {  
        let bytes = value.to_be_bytes();  
        self.append_bytes(&bytes);  
    }  
  
    pub fn append_u256(&mut self, value: &U256) {
        let bytes: Bytes = value.to_be_bytes(); 
        let mut arr = [0u8; 32];
        bytes.copy_into_slice(&mut arr);
        self.buffer.extend_from_slice(&arr);
    }

    fn append_g1_point(&mut self, point: &G1Point) {  
        let mut x_bytes = [0u8; 32];  
        let mut y_bytes = [0u8; 32];  
        point.x.serialize_compressed(&mut x_bytes[..]).unwrap();  
        point.y.serialize_compressed(&mut y_bytes[..]).unwrap();  
          
        self.append_bytes(&y_bytes); 
        self.append_bytes(&x_bytes); 
    }  

    pub fn get_challenge(&mut self) -> BytesN<32> {
        let crypto = self.env.crypto();
        let hash = crypto.keccak256(&self.buffer);
        self.buffer = Bytes::new(&self.env);
        hash.to_bytes()
    }

    pub fn generate_initial_challenge(&mut self, circuit_size: u32, num_inputs: u32) -> Fr {  
        self.append_u32(circuit_size);  
        self.append_u32(num_inputs);  
          
        let challenge_bytes = self.get_challenge();  
        Fr::from_be_bytes_mod_order(&challenge_bytes.to_array())  
    }  

      
    //generate challenges 
    pub fn generate_eta_challenge(&mut self, public_inputs: &[Fr], w1: &G1Point, w2: &G1Point, w3: &G1Point) -> (Fr, Fr, Fr) {  
  
        for input in public_inputs {  
            let mut bytes = [0u8; 32];  
            input.serialize_compressed(&mut bytes[..]).unwrap();  
            self.append_bytes(&bytes);  
        }  
          
        self.append_g1_point(w1);  
        self.append_g1_point(w2);  
        self.append_g1_point(w3);  
          
        let challenge_bytes = self.get_challenge();  
        let eta = Fr::from_be_bytes_mod_order(&challenge_bytes.to_array());  
        let eta_sqr = eta * eta;  
        let eta_cube = eta_sqr * eta;  
          
        (eta, eta_sqr, eta_cube)  
    } 

    pub fn generate_beta_challenge(&mut self, w4: &G1Point, s: &G1Point) -> Fr {  
        self.append_g1_point(w4);  
        self.append_g1_point(s);  
          
        let challenge_bytes = self.get_challenge();  
        Fr::from_be_bytes_mod_order(&challenge_bytes.to_array())  
    }  

    pub fn generate_gamma_challenge(&mut self) -> Fr {  
        self.append_bytes(&[0x01]);  
          
        let challenge_bytes = self.get_challenge();  
        Fr::from_be_bytes_mod_order(&challenge_bytes.to_array())  
    }  
    
    pub fn generate_alpha_challenge(&mut self, z: &G1Point, z_lookup: &G1Point) -> (Fr, Fr, Fr, Fr) {  
        self.append_g1_point(z);  
        self.append_g1_point(z_lookup);  
          
        let challenge_bytes = self.get_challenge();  
        let alpha = Fr::from_be_bytes_mod_order(&challenge_bytes.to_array());  
        let alpha_sqr = alpha * alpha;  
        let alpha_cube = alpha_sqr * alpha;  
        let alpha_quad = alpha_cube * alpha;  
          
        (alpha, alpha_sqr, alpha_cube, alpha_quad)  
    }  

    pub fn generate_zeta_challenge(&mut self, t1: &G1Point, t2: &G1Point, t3: &G1Point, t4: &G1Point) -> Fr {  
        self.append_g1_point(t1);  
        self.append_g1_point(t2);  
        self.append_g1_point(t3);  
        self.append_g1_point(t4);  
          
        let challenge_bytes = self.get_challenge();  
        Fr::from_be_bytes_mod_order(&challenge_bytes.to_array())  
    }  

    pub fn generate_nu_challenges(&mut self, quotient_eval: Fr, proof_data: &[u8]) -> [Fr; 31] {  

        let mut bytes = [0u8; 32];  
        quotient_eval.serialize_compressed(&mut bytes[..]).unwrap();  
        self.append_bytes(&bytes);  
        
        self.append_bytes(proof_data);  
          
        let mut challenges = [Fr::zero(); 31];  
        let base_challenge_bytes = self.get_challenge();  
        let base_challenge = Fr::from_be_bytes_mod_order(&base_challenge_bytes.to_array());  
          
        challenges[0] = base_challenge;  
          
        for i in 1..31 {  
            let mut hasher_input = [0u8; 33];  
            base_challenge.serialize_compressed(&mut hasher_input[..32]).unwrap();  
            hasher_input[32] = i as u8;  
              
            let crypto = self.env.crypto();  
            let hash = crypto.keccak256(&Bytes::from_slice(&self.env, &hasher_input));  
            challenges[i] = Fr::from_be_bytes_mod_order(&hash.to_array());  
        }  
          
        challenges  
    }  

    //Generate sumcheck challenges 
     pub fn generate_sumcheck_challenges(&mut self, proof: &Proof) -> [Fr; CONST_PROOF_SIZE_LOG_N] {  
        let mut sumcheck_challenges = [Fr::zero(); CONST_PROOF_SIZE_LOG_N];  
          
        for i in 0..CONST_PROOF_SIZE_LOG_N {  
    
            let mut univariate_chal = Bytes::new(&self.env);  
               
            let prev_challenge_bytes = self.get_challenge();  
            let prev_challenge = Fr::from_be_bytes_mod_order(&prev_challenge_bytes.to_array());  
              
            let mut challenge_bytes = [0u8; 32];  
            prev_challenge.serialize_compressed(&mut challenge_bytes[..]).unwrap();  
            univariate_chal.extend_from_slice(&challenge_bytes);  
              
            for j in 0..BATCHED_RELATION_PARTIAL_LENGTH {  
                let mut coeff_bytes = [0u8; 32];  
                proof.sumcheck_univariates[i][j].serialize_compressed(&mut coeff_bytes[..]).unwrap();  
                univariate_chal.extend_from_slice(&coeff_bytes);  
            }  
              
            let crypto = self.env.crypto();  
            let hash = crypto.keccak256(&univariate_chal);  
            let challenge = Fr::from_be_bytes_mod_order(&hash.to_array());  
                
            sumcheck_challenges[i] = self.split_challenge(challenge).0;  
              
            self.buffer = Bytes::new(&self.env);  
            self.append_bytes(&hash.to_array());  
        }  
          
        sumcheck_challenges  
    }  

    fn split_challenge(&self, challenge: Fr) -> (Fr, Fr) {  
        let challenge_bytes = {  
            let mut bytes = [0u8; 32];  
            challenge.serialize_compressed(&mut bytes[..]).unwrap();  
            bytes  
        };  
           
        let mut lo_bytes = [0u8; 32];  
        let mut hi_bytes = [0u8; 32];  
          
        lo_bytes[16..32].copy_from_slice(&challenge_bytes[16..32]);  
        hi_bytes[16..32].copy_from_slice(&challenge_bytes[0..16]);  
          
        let first = Fr::from_be_bytes_mod_order(&lo_bytes);  
        let second = Fr::from_be_bytes_mod_order(&hi_bytes);  
          
        (first, second)  
    }  
    
}


//ec operaitons 
pub fn combine_bytes<F: PrimeField>(a: &F, b: &F) -> F {
    let shift = F::from(2u128).pow(&[136u64]);
    *a + *b * shift
}

pub fn convert_proof_point<F: PrimeField>(input: &G1ProofPoint) -> G1Point {  
    let x = combine_bytes(&input.x_0, &input.x_1);  
    let y = combine_bytes(&input.y_0, &input.y_1);  
    G1Point { x, y }  
}  
  
pub fn ec_add<G: CurveGroup>(point0: G::Affine, point1: G::Affine) -> G::Affine {  
    (point0 + point1).into_affine()  
}  
  
pub fn ec_mul<G: CurveGroup>(point: G::Affine, scalar: G::ScalarField) -> G::Affine {  
    (point * scalar).into_affine()  
}  
  
pub fn ec_sub<G: CurveGroup>(point0: G::Affine, point1: G::Affine) -> G::Affine {
    (point0.into_group() - point1.into_group()).into_affine()
}

pub fn pairing_check(
    rhs: G1Affine,
    lhs: G1Affine,
    fixed_g2: G2Affine,
    vk_g2: G2Affine,
) -> bool {
    let pairing1 = Bn254::pairing(&rhs, &fixed_g2);
    let pairing2 = Bn254::pairing(&lhs, &vk_g2);

    let prod = pairing1.0 * pairing2.0;

    prod == Fq12::one()
}



#[cfg(test)]
mod test;
