use std::fs::File;
use std::io::{Read, Write};
use std::env;
use std::path::Path;
use std::net::{IpAddr, Ipv4Addr};
use libp2p::PeerId;
use openssl::pkey::PKey;
use openssl::symm::Cipher;
use sysinfo::System;
use systemstat::{System as SystemStat, Platform, data};
use std::net::{SocketAddr, TcpStream};
use std::io::{Error, ErrorKind};
use crate::error::P2pError;

pub(crate) fn read_key_or_generate_key() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let exe_path = env::current_exe()?;
    let cpu = sys.cpus().get(0).unwrap();
    let password = format!("{}@{}/{}/{}/{}/{}/{}/{}", exe_path.display(), System::host_name().unwrap(),
        System::distribution_id(), System::name().unwrap(), cpu.brand(),sys.cpus().len(), cpu.frequency(), sys.total_memory()/(1024*1024*1024));
    tracing::info!("password: {password}");

    let file_path = Path::new(".token_user.pem");
    let private_key = match file_path.exists() {
        false => {
            let private_key = PKey::generate_ed25519()?;
            let pem_key = private_key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), password.as_bytes())?;
            let mut file = File::create(file_path)?;
            file.write_all(&pem_key)?;
            private_key.raw_private_key()?
        }
        true => {
            let mut file = File::open(file_path)?;
            let mut key_data = Vec::new();
            file.read_to_end(&mut key_data)?;
            let private_key = PKey::private_key_from_pem_passphrase(&key_data, password.as_bytes())?;
            private_key.raw_private_key()?
        }
    };

    Ok(private_key)
}

pub(crate) fn get_ipaddr_from_netif() -> Result<Vec<Ipv4Addr>, Box<dyn std::error::Error>> {
    let sys_stat = SystemStat::new();
    let mut ipaddrs: Vec<Ipv4Addr> = Vec::new();
    match sys_stat.networks() {
        Ok(netifs) => {
            for netif in netifs.values() {
                let addrs = &netif.addrs;
                for addr in addrs.iter() {
                    match addr.addr {
                        data::IpAddr::V4(ipv4) => {
                            if (!ipv4.is_private() && !ipv4.is_loopback() && !ipv4.is_multicast())
                                || (ipv4.is_private() && !netif.name.starts_with("bridge") && !netif.name.starts_with("docker")) {
                                ipaddrs.push(ipv4);
                                tracing::info!("Networks {}: {}", netif.name, ipv4);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Err(x) => tracing::info!("\nNetworks: error: {}", x)
    };
    Ok(ipaddrs)
}

pub(crate) fn get_ipaddr_from_stream() -> Result<Ipv4Addr, Error> {
    let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(114,114,114,114)), 53);
    let stream = TcpStream::connect(socket_addr)?;
    let local_addr = stream.local_addr()?;
    let local_ip = local_addr.ip();
    tracing::info!("TcpStream local_ip: {}", local_ip);
    match local_ip {
        IpAddr::V4(ipv4) => Ok(ipv4),
        _ => Err(Error::new(ErrorKind::Other, "No IPv4 address found")),
    }
}

pub(crate) async fn get_ipaddr_from_public() -> Result<Ipv4Addr, P2pError> {
    let client = reqwest::Client::new();
    let response = client.get("https://ipinfo.io/ip").send().await?;
    let ip_str = response.text().await?;
    let ip_addr = ip_str.parse::<Ipv4Addr>()?;
    tracing::info!("Public_IP: {}", ip_addr);
    Ok(ip_addr)
}


pub(crate) fn get_short_id(peer_id: PeerId) -> String {
    let base58_peer_id = peer_id.to_base58();
    let short_peer_id = base58_peer_id.chars().skip(base58_peer_id.len() - 7).collect::<String>();
    short_peer_id
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

