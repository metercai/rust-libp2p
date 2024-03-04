use std::fs::File;
use std::io::{Read, Write};
use std::env;
use std::path::Path;
use openssl::pkey::PKey;
use openssl::symm::Cipher;
use sysinfo::{Components, Disks, Networks, System};

pub fn read_key_or_generate_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut sys = System::new_all();
    sys.refresh_all();
    println!("System: {:?}", sys);
    println!("=> disks:");
    let disks = Disks::new_with_refreshed_list();
    for disk in &disks {
        println!("{disk:?}");
    }
    let networks = Networks::new_with_refreshed_list();
    println!("=> networks:");
    for (interface_name, data) in &networks {
        println!("{interface_name},");
    }
    let components = Components::new_with_refreshed_list();
    println!("=> components:");
    for component in &components {
        println!("{component:?}");
    }
    let exe_path = env::current_exe()?;
    let password = format!("{}:{}:{:?}:{:?}:{:?}", exe_path.display(), sys.total_memory(), System::long_os_version(), System::host_name(), System::cpu_arch());
    println!("password: {password}");


    let file_path = Path::new(".token_user.pem");
    let private_key = match file_path.exists() {
        false => {
            let private_key = PKey::generate_ed25519()?;
            let pem_key = private_key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), password.as_bytes())?;
            let mut file = File::create(file_path)?;
            file.write_all(&pem_key)?;
            private_key.private_key_to_der()?
        }
        true => {
            let mut file = File::open(file_path)?;
            let mut key_data = Vec::new();
            file.read_to_end(&mut key_data)?;
            let private_key = PKey::private_key_from_pem_passphrase(&key_data, password.as_bytes())?;
            private_key.private_key_to_der()?
        }
    };

    Ok(private_key)
}

/*pub(crate) fn read_key_or_generate_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {

    //let key2 = pbkdf2_hmac_array::<Sha256, 20>(password, salt, n);
    let file_path = Path::new(".token_user.pem");
    let private_key = match file_path.exists() {
        false => {
            let mut csprng = OsRng;
            let private_key = SigningKey::generate(&mut csprng).to_bytes();
            let private_key_pkcs8_bytes = PrivateKeyInfo::try_from(private_key.as_ref()).unwrap()
                    .encrypt(csprng, password.as_bytes())?;
            //let private_key_pem = pem::encode(Pem::new("ENCRYPTED PRIVATE KEY", private_key_pkcs8_bytes.as_ref()));
            let private_key_pem =
                EncryptedPrivateKeyInfo::try_from(private_key_pkcs8_bytes).unwrap()
                    .to_pem(Default::default()).unwrap();

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(file_path)?;
            file.write_all(private_key_pem.as_ref())?;
            private_key
        },
        true => {
            let private_key_pem = fs::read_to_string(file_path)?;
            println!("File content:\n{}", private_key_pem);
            let enc_pk = EncryptedPrivateKeyInfo::try_from(pem::parse(private_key_pem).unwrap().contents()).unwrap();
            let private_key = enc_pk.decrypt(password).unwrap();
            private_key
        }
    };

    Ok(private_key)
}*/
