#![no_std]

extern crate alloc;  
use wee_alloc::WeeAlloc;  

#[global_allocator]  
static ALLOC: WeeAlloc = WeeAlloc::INIT;  

use core::ops::Mul;
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_serialize::{CanonicalDeserialize, Compress, Validate,CanonicalSerialize,SerializationError};
use ark_ec::{pairing::Pairing, CurveGroup,Group};
//use ark_ff::{Field, PrimeField};
use soroban_sdk::{contract, contractimpl, Bytes, Env};

#[contract]
pub struct BN254Contract;

fn serialize_g1(point: &G1) -> alloc::vec::Vec<u8> {  
    let mut temp_vec = alloc::vec::Vec::new();  
    point.into_affine().serialize_with_mode(&mut temp_vec, Compress::No).unwrap();  
    temp_vec  
}

fn deserialize_g1(bytes: &[u8]) -> Result<G1, SerializationError> {
    let point = G1Affine::deserialize_with_mode(bytes, Compress::No, Validate::Yes)?;
    Ok(point.into())
}

// fn serialize_g2(env: &Env, point: &G2) -> Bytes {  
//     let mut temp_vec = Vec::new();  
//     point.into_affine().serialize_with_mode(&mut temp_vec, Compress::No).unwrap();  
      
//     Bytes::from_slice(env, &temp_vec)  
// }


fn deserialize_g2(bytes: &[u8]) -> Result<G2, SerializationError> {
    let point = G2Affine::deserialize_with_mode(bytes,Compress::No, Validate::Yes)?;
    Ok(point.into())
}

// fn serialize_fr(env: &Env, scalar: &Fr) -> Bytes {  
//     let mut temp_vec = alloc::vec::Vec::new();  
//     scalar.serialize_with_mode(&mut temp_vec, Compress::No).unwrap();  
      
//     Bytes::from_slice(env, &temp_vec)  
// }

fn deserialize_fr(bytes: &[u8]) -> Result<Fr, SerializationError> {  
    Fr::deserialize_with_mode(bytes, Compress::No, Validate::Yes)  
}


#[contractimpl]
impl BN254Contract {  
  
    pub fn generate_g1_point(env: Env, scalar: Bytes) -> Bytes {    

        let mut buffer = [0u8; 32]; 
          
        let scalar_fr = if scalar.len() as usize == buffer.len() {  
            scalar.copy_into_slice(&mut buffer);  
            match deserialize_fr(&buffer[..]) {    
                Ok(s) => s,    
                Err(_) => Fr::from(1u32),    
            }  
        } else {  
            Fr::from(1u32) 
        };  
          
        let g1_gen = G1::generator();    
        let point = g1_gen.mul(scalar_fr);    
        
        let serialized = serialize_g1(&point);    
        Bytes::from_slice(&env, &serialized)    
    }
 
    pub fn scalar_mul_g1(env: Env, point_bytes: Bytes, scalar_bytes: Bytes) -> Bytes {  
       
        let mut point_buffer = [0u8; 48];  
        if point_bytes.len() as usize != point_buffer.len() {  
            return Bytes::from_slice(&env, &[0u8]);  
        }  
        point_bytes.copy_into_slice(&mut point_buffer);  
          
        let point = match deserialize_g1(&point_buffer[..]) {  
            Ok(p) => p,  
            Err(_) => return Bytes::from_slice(&env, &[0u8]),  
        };  
          
        let mut scalar_buffer = [0u8; 32]; 
        if scalar_bytes.len() as usize != scalar_buffer.len() {  
            return Bytes::from_slice(&env, &[0u8]);  
        }  
        scalar_bytes.copy_into_slice(&mut scalar_buffer);  
          
        let scalar = match deserialize_fr(&scalar_buffer[..]) {  
            Ok(s) => s,  
            Err(_) => return Bytes::from_slice(&env, &[0u8]),  
        };  
          
        let result = point.mul(scalar);  
          
        let serialized = serialize_g1(&result);  
        Bytes::from_slice(&env, &serialized)  
    }   

    pub fn add_g1_points(env: Env, point1_bytes: Bytes, point2_bytes: Bytes) -> Bytes {  
        
        let mut point1_buffer = [0u8; 48];
        if point1_bytes.len() as usize != point1_buffer.len() {  
            return Bytes::from_slice(&env, &[0u8]);  
        }  
        point1_bytes.copy_into_slice(&mut point1_buffer);  
          
        let point1 = match deserialize_g1(&point1_buffer[..]) {  
            Ok(p) => p,  
            Err(_) => return Bytes::from_slice(&env, &[0u8]),  
        };  
          
       
        let mut point2_buffer = [0u8; 48];  
        if point2_bytes.len() as usize != point2_buffer.len() {  
            return Bytes::from_slice(&env, &[0u8]);  
        }  
        point2_bytes.copy_into_slice(&mut point2_buffer);  
          
        let point2 = match deserialize_g1(&point2_buffer[..]) {  
            Ok(p) => p,  
            Err(_) => return Bytes::from_slice(&env, &[0u8]),  
        };  
          
        let result = point1 + point2;  
          
        let serialized = serialize_g1(&result);  
        Bytes::from_slice(&env, &serialized)  
    }
    
    pub fn perform_pairing(env: Env, g1_bytes: Bytes, g2_bytes: Bytes) -> Bytes {  
        // For G1 point deserialization  
        let mut g1_buffer = [0u8; 48]; // Adjust size based on G1 point serialization format  
        if g1_bytes.len() as usize != g1_buffer.len() {  
            return Bytes::from_slice(&env, &[0u8]);  
        }  
        g1_bytes.copy_into_slice(&mut g1_buffer);  
          
        let g1_point = match deserialize_g1(&g1_buffer[..]) {  
            Ok(p) => p,  
            Err(_) => return Bytes::from_slice(&env, &[0u8]),  
        };  
          
        // For G2 point deserialization  
        let mut g2_buffer = [0u8; 96]; // Adjust size based on G2 point serialization format  
        if g2_bytes.len() as usize != g2_buffer.len() {  
            return Bytes::from_slice(&env, &[0u8]);  
        }  
        g2_bytes.copy_into_slice(&mut g2_buffer);  
          
        let g2_point = match deserialize_g2(&g2_buffer[..]) {  
            Ok(p) => p,  
            Err(_) => return Bytes::from_slice(&env, &[0u8]),  
        };  
          
        // Fix the unused variable warning by prefixing with underscore  
        let _pairing_result = Bn254::pairing(g1_point, g2_point);  
          
        // Use the pairing result directly without conditional compilation  
        let mut temp_vec = alloc::vec::Vec::new();  
        _pairing_result.0.serialize_with_mode(&mut temp_vec, Compress::No).unwrap();  
        Bytes::from_slice(&env, &temp_vec)  
    }
    
}  
