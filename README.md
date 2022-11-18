```sh
USAGE:
    crypto [FLAGS] --password <password> [INPUT]

FLAGS:
    -d, --decrypt    Decrypts the input
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -p, --password <password>    The encryption password [env: CRYPTO_PWD=]

ARGS:
    <INPUT>
```

# Examples

### Environment variables

Use an environment variable instead of the `-p` argument
```bash
CRYPTO_PWD=$(pass mypass) crypto secret
```

### Strings

Encrypt a string

```bash
crypto -p passwd secret
```

Decrypt a string
```bash
crypto -p passwd -d EAAAAAAAAAAuF8Z9UL2+1VYLOC24x+ppEAAAAAAAAADLYU9zTtqyLwb7mbiGhUSS
```

### Binary data

Encrypt
```bash
cat file.zip | crypto -p secret > file.zip.crypt
```
Decrypt
```bash
cat file.zip.crypt | crypto -p secret -d > file.zip
```

