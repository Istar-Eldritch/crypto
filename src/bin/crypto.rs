//! CLI to the [cloudapi::Crypto](../cloudapi/crypto/index.html) module
//!
//! # Usage
//!
//! ```text
//! USAGE:
//!     crypto [FLAGS] --password <password> [INPUT]
//!
//! FLAGS:
//!     -d, --decrypt    Decrypts the input
//!     -h, --help       Prints help information
//!     -V, --version    Prints version information
//!
//! OPTIONS:
//!     -p, --password <password>    The encryption password [env: CRYPTO_PWD=]
//!
//! ARGS:
//!     <INPUT>
//! ```
//!
//! # Examples
//!
//! ### Environment variables
//!
//! Use an environment variable instead of the `-p` argument
//! ```bash
//! CRYPTO_PWD=$(pass mypass) crypto secret
//! ```
//!
//! ### Strings
//!
//! Encrypt a string
//!
//! ```bash
//! crypto -p passwd secret
//! ```
//!
//! Decrypt a string
//! ```bash
//! crypto -p passwd -d EAAAAAAAAAAuF8Z9UL2+1VYLOC24x+ppEAAAAAAAAADLYU9zTtqyLwb7mbiGhUSS
//! ```
//!
//! ### Binary data
//!
//! Encrypt
//! ```bash
//! cat file.zip | crypto -p secret > file.zip.crypt
//! ```
//! Decrypt
//! ```bash
//! cat file.zip.crypt | crypto -p secret -d > file.zip
//! ```

use clap::{App, Arg};
use crypto::Crypto;
use std::io::{self, Read, Write};
use thiserror::Error;

fn main() {
    pretty_env_logger::init();

    let matches = App::new("crypto")
        .version("0.1")
        .about("Encryption & Decryption CLI")
        .arg(
            Arg::with_name("password")
                .short("p")
                .long("password")
                .takes_value(true)
                .env("CRYPTO_PWD")
                .required(true)
                .help("The encryption password"),
        )
        .arg(
            Arg::with_name("decrypt")
                .short("d")
                .long("decrypt")
                .takes_value(false)
                .help("Decrypts the input"),
        )
        .arg(Arg::with_name("INPUT"))
        .get_matches();

    let password = matches.value_of("password").unwrap();

    let crypto = Crypto::new(&password);

    let input = matches
        .value_of("INPUT")
        .map(|v| Vec::from(v.as_bytes()))
        .ok_or(()) // Transform option into result
        .or_else(|_| read_input());

    if let Err(e) = input {
        let msg = match e {
            ReadErrors::NotExpectingInput => format!(
                r#"
error: No input provided

{}

For more information try --help
"#,
                matches.usage()
            ),
            e => format!("{}", e),
        };
        write_output(msg.as_bytes()).unwrap();
        std::process::exit(1);
    }

    let result: Result<Vec<u8>, Vec<u8>> = if matches.is_present("decrypt") {
        decrypt(&crypto, input.unwrap()).map_err(|e| format!("{}", e).as_bytes().to_vec())
    } else {
        crypto
            .encrypt(&input.unwrap())
            .map(|out| out.as_bytes().to_vec())
            .map_err(|e| format!("{}", e).as_bytes().to_vec())
    };
    match result {
        Ok(out) => {
            write_output(&out).unwrap();
            std::process::exit(0)
        }
        Err(out) => {
            write_err(&out).unwrap();
            std::process::exit(1);
        }
    }
}

#[derive(Error, Debug)]
enum ReadErrors {
    #[error("Error reading input: {0}")]
    OnRead(#[from] io::Error),
    #[error("Must provide some input")]
    NotExpectingInput,
}

fn read_input() -> Result<Vec<u8>, ReadErrors> {
    let mut buf: Vec<u8> = Vec::new();
    let stdin = io::stdin();
    if atty::isnt(atty::Stream::Stdin) {
        let mut handle = stdin.lock();
        handle.read_to_end(&mut buf).map_err(ReadErrors::OnRead)?;
        return Ok(buf);
    }
    Err(ReadErrors::NotExpectingInput)
}

#[derive(Error, Debug)]
#[error("Write error: {0}")]
struct WriteError(#[from] io::Error);

fn write_output(output: &[u8]) -> Result<(), WriteError> {
    io::stdout().write_all(&output).map_err(WriteError)
}

fn write_err(output: &[u8]) -> Result<(), WriteError> {
    io::stderr().write_all(&output).map_err(WriteError)
}

#[derive(Error, Debug)]
enum DecryptErrors {
    #[error("Invalid input: {0}")]
    InvalidInput(#[from] std::string::FromUtf8Error),
    #[error("Decryption error: {0}")]
    DecryptionError(#[from] Box<dyn std::error::Error>),
}

fn decrypt(crypto: &Crypto, encrypted_input: Vec<u8>) -> Result<Vec<u8>, DecryptErrors> {
    String::from_utf8(encrypted_input)
        .map_err(DecryptErrors::InvalidInput)
        .and_then(|input| {
            crypto
                .decrypt::<Vec<u8>>(&input)
                .map_err(|e| DecryptErrors::DecryptionError(e))
        })
}
