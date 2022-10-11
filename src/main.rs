use std::io::Write;
use std::io::Read;
use std::fs::read;
use std::env::args;

use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::Message;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::armor::Writer as ArmorWriter;
use sequoia_openpgp::armor::Kind;
use mail_builder::MessageBuilder;
use mail_builder::mime::MimePart;

fn main() {
        let mut argv = args();
        argv.next();
        let fp_s = argv.next().unwrap();
        let msg = Message::from_file(fp_s).unwrap();

        let mut msg_w = ArmorWriter::new(Vec::new(), Kind::Message).unwrap();
        msg_w.write_all(msg.to_vec().unwrap().as_ref());
        let msg_b = msg_w.finalize().unwrap();
        let msg_s = String::from_utf8_lossy(&msg_b);

        let enc_version_part = MimePart::new_binary(
            "application/pgp-encrypted",
            "Version: 1".as_bytes(),
            );

        let enc_contents_part = MimePart::new_text_other(
            "application/octet-stream",
            msg_s,
            );

        let enc_envelope = MimePart::new_multipart(
            "multipart/encrypted; protocol=\"application/pgp-encrypted\"",
            vec![
                enc_version_part,
                enc_contents_part,
            ],
            )
            .inline();

        let eml = MessageBuilder::new()
            .from(("Forro contact form", "no-reply@holbrook.no"))
            .to(("Louis Holbrook", "l@holbrook.no"))
            .subject("Rust pgp enc message bridge")
            .body(enc_envelope);

        println!("{}", eml.write_to_string().unwrap());
}
