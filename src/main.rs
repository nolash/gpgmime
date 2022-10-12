use std::io::Write;

use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::Message;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::armor::Writer as ArmorWriter;
use sequoia_openpgp::armor::Kind;
use mail_builder::MessageBuilder;
use mail_builder::mime::MimePart;
use clap::App;
use clap::Arg;

struct Settings {
    to: String,
    from: String,
    subject: String,
    path: String,
}

impl Settings {
    fn from_args() -> Settings {
        let mut o = App::new("gpgmime");
        o = o.version(env!("CARGO_PKG_VERSION"));
        o = o.author(env!("CARGO_PKG_AUTHORS"));
        o = o.arg(
            Arg::with_name("to")
                .long("to")
                .short("t")
                .value_name("Email recipient")
                .takes_value(true)
                .required(true)
                );
        o = o.arg(
            Arg::with_name("from")
                .long("from")
                .short("f")
                .value_name("Email sender")
                .takes_value(true)
                .required(true)
                );
        o = o.arg(
            Arg::with_name("subject")
                .long("subject")
                .short("s")
                .value_name("Email subject")
                .takes_value(true)
                .required(true)
                );
        o = o.arg(
            Arg::with_name("PATH")
                .help("Path to PGP message")
                .required(true)
                );
        let arg = o.get_matches();
        let settings = Settings{
            to: arg.value_of("to").unwrap().to_string(),
            from: arg.value_of("from").unwrap().to_string(),
            subject: arg.value_of("subject").unwrap().to_string(),
            path: arg.value_of("PATH").unwrap().to_string(),
        };
        settings
    }
}


fn main() {
        let settings = Settings::from_args();

        let msg = Message::from_file(settings.path).unwrap();

        let mut msg_w = ArmorWriter::new(Vec::new(), Kind::Message).unwrap();
        let _c = msg_w.write_all(msg.to_vec().unwrap().as_ref());
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

        let subject: &str = settings.subject.as_ref();
        let eml = MessageBuilder::new()
            .from((settings.from.as_ref(), settings.from.as_ref()))
            .to((settings.to.as_ref(), settings.to.as_ref()))
            .subject(subject)
            .body(enc_envelope);

        println!("{}", eml.write_to_string().unwrap());
}
