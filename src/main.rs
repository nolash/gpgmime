#![crate_name = "gpgmime"]

//! gpgme creates multipart/encrypted emails from PGP messages.
//!
//! This multipart/encrypted structure can be successfully parsed 
//! and decrypted inline by my favorite MUA, [mutt](http://mutt.org).
//!
//! Checking that it works - or getting it to work - with more PGP
//! capable MUAs wouldn't hurt.
//!
//! 
//! ## Compatibility
//!
//! The tool parses both `.gpg` and `.asc` as input.
//!
//!
//! ## Example
//!
//! Let the follwing be the *ciphertext* stored in a file `msg.asc`
//!
//! ``` ignore,
//! -----BEGIN PGP MESSAGE-----
//!
//! hQGMA1IUfpa99cfFAQv/YrkKsUAo+jlSj3u+pSTcx+eNtCRgv3LHUUV1O3BpDMGp
//! tJYQrq+tRqhT29jnEZdJ+engC/gUHZYGOCburWFIKkStH1G4x5V4AWICtDcozPpK
//! ENIihA3kncbMsJrFcpgX4wmqA6c28ao9fzEGPcGWvA1jUV4g6qukQ2lOYgbmK2O6
//! wD5omaKLBguNVW6/PcTQ32kP4sGKwzS5B9R1X0FY7e3HJxMy0lnOpNQRY+g5AJZ0
//! ryncq+PPUYmjULCtr/BPm8idX2TBStx+1iqlvYQiW5x3tQIocWARWqILtNeYdHZF
//! a1CRSekj1bw4o5RzkJq92a9XqyiKlqna7X+W6E+59ZvoVUM3KgzCQ0MJkv1yQCo1
//! VX9kLoQ1ia658rsDg0YCZUyJ/kvD3z5gcLEL9/WRhlhbwfeUa6pkUUtk3TbAjqdb
//! GTj7wJDMUdA+Uuo5U5gglEL+Fl7wjDa4GnfTudtcfG0ImAoW433DstVp4Z7Qk2cW
//! uAprBVHHJSR+fNjszWhU0j8BxgsH/FeK87rbCgPvzZ1xWan4kdCfZXWrAt6ZV90U
//! Ic3i1AcP/R4tZ5oOxpLBXjkuXaOxI7YQ7LLI25t/Udo=
//! =YHyf
//! -----END PGP MESSAGE-----
//! ```
//! 
//! An example command and output is:
//!
//! ```
//! From: "foo@bar.com" <foo@bar.com>
//! To: "merman@greyskull.com" <merman@greyskull.com>
//! Subject: Skeletor is looking a bit pale
//! Message-ID: <171d5d0aa79de7cf.2c1958e5681b1f5f.1dc0ff8081f726a3@piano>
//! Date: Wed, 12 Oct 2022 15:48:57 +0000
//! Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; 
//!         boundary="171d5d0aa79eef5a_ca50d29ee7659b74_1dc0ff8081f726a3"
//! Content-Disposition: inline
//!
//!
//! --171d5d0aa79eef5a_ca50d29ee7659b74_1dc0ff8081f726a3
//! Content-Type: application/pgp-encrypted
//! Content-Transfer-Encoding: base64
//!
//! VmVyc2lvbjogMQ==
//!
//! --171d5d0aa79eef5a_ca50d29ee7659b74_1dc0ff8081f726a3
//! Content-Type: application/octet-stream; charset="utf-8"
//! Content-Transfer-Encoding: 7bit
//!
//! -----BEGIN PGP MESSAGE-----
//!
//! wcDMA1IUfpa99cfFAQv/ReJTs3mkbFYI9ifay1jhL1XW5u9cDMFTymdxMtWUhJvl
//! AM5AgWPSnwfVVaS9Ger2robtLsR5UeAjNSOGXg8Vpu7SsbQGsDXdScCgvwEmSPPU
//! atJ+qdw/wPKR2GTD41hypJDsIeoT9l9lfSIBgzXdu+PNrryLFzqpI+q8y3KMOjTG
//! W52lvulIhYrFgRzhhOaX8Ss3Wnx7j1+4KXsvk0VY+rTdM0krsmEgzXHfHGECgKga
//! zlYQ3c4OhpnsmYi0+rpzCqbBrbtxDdMuBif7nbzYettcrkQssRuS41mFHHYuJWu4
//! A8fkoFmjlz5NVEXZSdsnMyPV6lSE9IcllUuFzKXPAGBy3xNay7JdcPU/1C7iylOh
//! M9mrfoe1gpPRefwXrjkiVuJ/uhYwgCxcIdzmgJ7XBtoBvZzNt440pP+bZqCGJgPt
//! HlmBvtGY5F6uopRC1e+PH7a+vIYss5rmJ4OQGdvWRgj2RDPo9cIfAsU6sFP530T6
//! ErzvOCXiYDv+9IPy7LzG0j8BGdQeIVYbHWRYxc3aQhlfSDvR6WYMWAnmXNZYUiEW
//! QS34XWww8FHxBGWnj8DbVXuvVYdjeiSteTdDmC4fsUY=
//! =dhci
//! -----END PGP MESSAGE-----
//!
//! --171d5d0aa79eef5a_ca50d29ee7659b74_1dc0ff8081f726a3--
//!
//! ```
//!
//!
//! ## Shortcomings
//!
//! - The application/pgp-encrypted field will contain `Version: 1`
//! no matter the version of the message.

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


#[doc(hidden)]
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
