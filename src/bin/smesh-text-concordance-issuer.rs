use std::io::{Read as _, Write as _};
use std::path::PathBuf;

use smesh_a2a::{
    IssuerRoleV1, TextConcordanceCandidatePacketV1,
    sign_text_concordance_evidence_from_private_file,
};

const MAX_PACKET_BYTES: u64 = 2_000_000;

fn main() {
    if run().is_err() {
        eprintln!("semantic issuer request rejected");
        std::process::exit(1);
    }
}

fn run() -> Result<(), ()> {
    let mut role = None;
    let mut identity = None;
    let mut key_file = None;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next().ok_or(())?;
        match flag.as_str() {
            "--role" if role.is_none() => {
                role = Some(match value.as_str() {
                    "review" => IssuerRoleV1::Review,
                    "test" => IssuerRoleV1::Test,
                    "contradiction" => IssuerRoleV1::Contradiction,
                    _ => return Err(()),
                });
            }
            "--identity" if identity.is_none() && !value.is_empty() && value.len() <= 512 => {
                identity = Some(value);
            }
            "--key-file" if key_file.is_none() => key_file = Some(PathBuf::from(value)),
            _ => return Err(()),
        }
    }
    let role = role.ok_or(())?;
    let identity = identity.ok_or(())?;
    let key_file = key_file.ok_or(())?;

    let mut input = Vec::new();
    std::io::stdin()
        .take(MAX_PACKET_BYTES + 1)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    if input.len() > usize::try_from(MAX_PACKET_BYTES).map_err(|_| ())? {
        return Err(());
    }
    let packet: TextConcordanceCandidatePacketV1 =
        serde_json::from_slice(&input).map_err(|_| ())?;
    let signed =
        sign_text_concordance_evidence_from_private_file(&packet, role, identity, &key_file)
            .map_err(|_| ())?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &signed).map_err(|_| ())?;
    output.write_all(b"\n").map_err(|_| ())?;
    output.flush().map_err(|_| ())
}
