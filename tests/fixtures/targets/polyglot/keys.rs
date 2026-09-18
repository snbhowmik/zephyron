use rsa::RsaPrivateKey;
fn main() {
    let mut rng = rand::thread_rng();
    let _key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
}
