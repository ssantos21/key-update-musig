use secp256k1_zkp::{Secp256k1, SecretKey, rand, musig::MusigKeyAggCache, Scalar};

fn t1_proof(client_1_secret_key: &SecretKey, x1: &Scalar, t1: &SecretKey) {

    let x1_seckey =  SecretKey::from_slice(&x1.to_be_bytes()).unwrap();

    let negated_x1 = x1_seckey.negate();

    let scalar_negated_x1 = Scalar::from(negated_x1);

    let o1 = t1.add_tweak(&scalar_negated_x1).unwrap();

    println!("o1: {}", hex::encode(o1.secret_bytes()));

    assert_eq!(o1, *client_1_secret_key);
}

fn t2_proof(client_2_secret_key: &SecretKey, t1_scalar: &Scalar, t2: &SecretKey) {
    
    let negated_t2 = t2.negate();

    let o2 = negated_t2.add_tweak(t1_scalar).unwrap();

    println!("o2: {}", hex::encode(o2.secret_bytes()));

    assert_eq!(o2, *client_2_secret_key);
}

fn new_enclave_privkey_proof(enclave_privkey: &SecretKey, t2: &SecretKey, x1: &Scalar, new_enclave_privkey: &SecretKey) {

    let negated_t2 = t2.negate();

    let t2_x1 = negated_t2.add_tweak(x1).unwrap();

    let server_seckey = new_enclave_privkey.add_tweak(&Scalar::from(t2_x1)).unwrap();

    println!("server_seckey: {}", hex::encode(server_seckey.secret_bytes()));

    assert_eq!(server_seckey, *enclave_privkey);
}

fn final_proof(client_1_secret_key: &SecretKey, server_secret_key: &SecretKey, client_2_secret_key: &SecretKey, new_server_secret_key: &SecretKey) {
    
        let s1o1 = client_1_secret_key.add_tweak(&Scalar::from(server_secret_key.to_owned())).unwrap();
    
        let s2o2 = client_2_secret_key.add_tweak(&Scalar::from(new_server_secret_key.to_owned())).unwrap();
    
        assert_eq!(s1o1, s2o2);
}

fn main() {
    let secp = Secp256k1::new();

    let client_1_secret_key = SecretKey::new(&mut rand::thread_rng());
    let client_1_pubkey = client_1_secret_key.public_key(&secp);

    println!("client_1_secret_key: {}", hex::encode(client_1_secret_key.secret_bytes()));

    let server_secret_key = SecretKey::new(&mut rand::thread_rng());
    let server_pubkey = server_secret_key.public_key(&secp);

    println!("server_secret_key: {}", hex::encode(server_secret_key.secret_bytes()));

    println!("client_1_pubkey: {}", client_1_pubkey.to_string());
    println!("server_pubkey: {}", server_pubkey.to_string());

    println!("Combining public keys...");

    let key_agg_cache = MusigKeyAggCache::new(&secp, &[client_1_pubkey, server_pubkey]);
    let agg_pk = key_agg_cache.agg_pk();
 
    println!("agg_pk: {}", agg_pk.to_string());

    let client_2_secret_key = SecretKey::new(&mut rand::thread_rng());
    let client_2_pubkey = client_2_secret_key.public_key(&secp);

    println!("client_2_secret_key: {}", hex::encode(client_2_secret_key.secret_bytes()));

    let x1: Scalar = Scalar::random();

    let t1 = client_1_secret_key.add_tweak(&x1).unwrap();

    t1_proof(&client_1_secret_key, &x1, &t1);

    // t2 = t1 - o2

    let t1_scalar = Scalar::from(t1);

    let negated_client_2_secret_key = client_2_secret_key.negate();

    let t2: SecretKey = negated_client_2_secret_key.add_tweak(&t1_scalar).unwrap();

    println!("t2: {}", hex::encode(t2.secret_bytes()));

    t2_proof(&client_2_secret_key, &t1_scalar, &t2);

    let t2_a = t1.add_tweak(&Scalar::from(negated_client_2_secret_key)).unwrap();

    assert_eq!(t2, t2_a);

    // new_enclave_privkey = enclave_privkey + t2 - x1

    let server_secret_key_t2 = server_secret_key.add_tweak(&Scalar::from(t2)).unwrap();

    let x1_seckey = SecretKey::from_slice(&x1.to_be_bytes()).unwrap();

    let negated_x1 = x1_seckey.negate();

    let scalar_negated_x1 = Scalar::from(negated_x1);

    let new_enclave_privkey = server_secret_key_t2.add_tweak(&scalar_negated_x1).unwrap();

    println!("new_enclave_privkey: {}", hex::encode(new_enclave_privkey.secret_bytes()));

    new_enclave_privkey_proof(&server_secret_key, &t2, &x1, &new_enclave_privkey);

    final_proof(&client_1_secret_key, &server_secret_key, &client_2_secret_key, &new_enclave_privkey);

    let key_agg_cache = MusigKeyAggCache::new(&secp, &[client_2_pubkey, new_enclave_privkey.public_key(&secp)]);
    let agg_pk2 = key_agg_cache.agg_pk();
 
    println!("agg_pk2 {}", agg_pk2.to_string());

    println!("{} != {}", agg_pk, agg_pk2.to_string());
}
