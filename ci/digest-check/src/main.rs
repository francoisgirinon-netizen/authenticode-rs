use object::read::pe::{PeFile32, PeFile64};
use sha2::{Digest, Sha256};

fn main() {
    for path in std::env::args().skip(1) {
        let data = std::fs::read(&path).unwrap();
        let mut hasher = Sha256::new();
        if let Ok(pe) = PeFile64::parse(&*data) {
            authenticode::authenticode_digest(&pe, &mut hasher).unwrap();
        } else {
            let pe = PeFile32::parse(&*data).unwrap();
            authenticode::authenticode_digest(&pe, &mut hasher).unwrap();
        }
        let digest: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        println!("authenticode_rs={digest}");
    }
}
