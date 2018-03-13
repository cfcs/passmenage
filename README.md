# Work-in-progress: PassMenage
![Build status](https://travis-ci.org/cfcs/passmenage.svg?branch=master)

This is a password manager library implementing basic operations on a data
structure that can be used to store passwords.

We're still working on the library, so things may change, and there may be BUGS.

## Cmdliner application

An example implementation using [Cmdliner](https://github.com/dbuenzli/cmdliner)
is provided in [./app/passmenage_cli.ml].

The binary provides the following sub-commands:
```
COMMANDS
       add
           Add an entry to a category.

       get
           Get an entry from the password file.

       init
           Initialize a new password file

       list
           List categories, or entries in a specific category

       pretty-print
           Pretty-print the state (INCLUDING PASSWORDS)
```

A manpage is available with `./passmenage_cli.native --help`

## Data structures

The internal data structure is a JSON tree:

```javascript
{ /* encrypted, OCaml struct name: `state` */
  configuration:
  [ /* list of string tuples, OCaml struct name: `configuration` */
    ["entry 1", "value 1"],
    ["entry 2", "value 2"],
  ],

  categories: /* list of associative dictionaries, which may be nested */
  [
    { /* OCaml struct name: `category` */
      /* each category may optionally be encrypted with a separate key */
      name: "category 1",
      entries: /* list of associative dictionaries */
        [
          { /* OCaml struct name: `entry` */
            name: "my github password",
            passphrase: "123456",
            metadata:
              [ /* list of string tuples */
                ["url", "https://github.com/signin"],
                ["last_changed", "2017-12-01"],
              ]
          },
        ],
      subcategories: [] /* a list of `category` objects */
    },
  ]
}
```

The tree is always encrypted when serialized.
Each category may be independently encrypted to give the user control over the
date loaded in memory during a given session.

The encryption is performed using
[Nocrypto](https://github.com/mirleft/ocaml-nocrypto)'s
[AES-CCM](https://en.wikipedia.org/wiki/CCM_mode) primitive with a 128-bit MAC
, a random 256-bit key, and a random 104-bit nonce.
New random values for the key and nonce are generated on each
serialization/encryption.
I couldn't find any documentation that references a standardized instance
of AES-CCM in `nocrypto`, so there's no telling what actually goes on under
the hood inside this library without reading the source code, which I'm not
smart enough to understand. YOLO.

The random key is encrypted with the
`scrypt_enc_buf(maxmem = 1MB, maxtime = 1 second)` primitive from
[Tarsnap](https://github.com/Tarsnap/scrypt/blob/master/lib/scryptenc/scryptenc.h)
(a [KDF](https://wikipedia.org/wiki/Key_derival_function) based on
`HMAC-SHA-256` and `AES-CTR-256`) using a user-provided passphrase,
and the result is stored in a JSON object:

```javascript
{ /* OCaml struct name: `encrypted_data` */
  kdf: "scrypt...", /* the output from scrypt_enc_buf() */

  nonce: "AAAAAA", /* 32-byte random value */

  ciphertext: "BBBBBB", /* ciphertext and MAC from AES-CCM */
}
```

## Using the library

The [mli interface specification](./lib/passmenage.mli) contains most of the
information needed to use the library.

A nice HTML representation can be generated using `topkg doc` if you have the
`topkg-care` package installed from `opam`.

## TODO

- [ ] figure out what breed of AES-CCM nocrypto implements
- [ ] add version information to the `state` structure
- [ ] add version information to the `encrypted_data` structure
- [ ] ensure key/name uniqueness
  - [ ] on `configuration` and `metadata` lists
  - [ ] on entries and categories
  - [ ] consider not exposing raw structs to enforce this invariant
- [ ] provide `UPSERT` and similar helper functions to operate on the data
