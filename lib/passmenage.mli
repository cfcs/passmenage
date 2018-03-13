(** PassMenage password manager library *)

type encrypted_data
(** Abstract type for encrypted data. *)

type configuration = (string * string) list
(** Application can store whatever here. *)

type entry =
  { name: string ; (** A user-defined name. Must be unique in a category. *)
    passphrase: string ; (** The stored passphrase. *)
    metadata: (string * string) list ; (** Application-defined metadata *)
  }

type crypt_category = { name : string ;
                        category_ciphertext : encrypted_data ;}

type plain_category =
  { name : string ;
    entries : entry list ;
    subcategories: category list ;
    encryption_key : string option ;
    (** if set, the category will be encrypted with the passphrase when the
        category is serialized.*)
  }
and category = Plain_category of plain_category
             | Crypt_category of crypt_category

type state = { conf : configuration ;
               categories: category list ;
             }
(** The main tree / data structure.*)

open Rresult

(** {1:pp Pretty-printers} *)

val pp_entry : Format.formatter -> entry -> unit

val pp_category : Format.formatter -> category -> unit

val pp_state : Format.formatter -> state -> unit

(** {1:new_passphrases Generating new passphrases} *)

val generate_passphrase :
  int -> char list -> (string, [> R.msg ]) result
(** [generate_passphrase length alphabet] generates a string of [length]
    characters randomly picked from [alphabet].*)

val decimals : char list
(** See {{!generate_passphrase}generate_passphrase}.
    The set of decimals from [0-9].*)

val upper : char list
(** See {{!generate_passphrase}generate_passphrase}.
    The set of uppercase letters from [A-Z]. *)

val lower : char list
(** See {{!generate_passphrase}generate_passphrase}.
    The set of lowercase letters from [a-z]. *)

val alphanum : char list
(** See {{!generate_passphrase}generate_passphrase}.
    The set consisting of [decimals] @ [upper] @ [lower] *)

val symbols : char list
(** See {{!generate_passphrase}generate_passphrase}.
    A set of various symbols reachable on a US keyboard. *)

val all_chars : char list
(** See {{!generate_passphrase}generate_passphrase}.
    The set consisting of [alphanum] @ [symbols]*)

(** {1:encryption Dealing with en-/decryption:} *)

val encrypt_category : plain_category -> (crypt_category, [> R.msg]) result
(** encrypt a category using the [encryption_key] contained in the record,
    error if [encryption_key] is None *)

val decrypt_category :
  passphrase:string ->
  crypt_category ->
  (plain_category, [> R.msg ]) result
(** [decrypt_category ~key encrypted] is [encrypted] decrypted using [key].
    The key is stored in the result so that it may be re-encrypted again using
    {{!encrypt_category}encrypt_category}.*)

val serialize_state : passphrase:string -> state -> string
(** [serialize_state ~key state] is the [state] encrypted with [key] and
    serialized to a string. *)


val unserialize_state : passphrase:string -> string ->
  (state, [> R.msg ]) result
(** [unserialize_state ~key encrypted] is the state tree decrypted from
    [encrypted] using [key]. *)

(** {1:helpers Helper function for updating the tree:} *)

val name_of_category : category -> string
(** Retrieve the name of a category.*)

val get_category : state -> string -> (category, [> R.msg]) result
(** [get_category state name] retrieves a category from the [state] tree,
    or an error if no entry of [name] exists.*)

val insert_new_category : state -> category -> (state, [> R.msg]) result
(** [insert_new_category state new] inserts [new] into the state tree.
    Returns an error if a category of the same name already exists. *)

val update_category : state -> plain_category -> state
(** [update_category state new] replaces the category sharing [new]'s name
    in the [state] tree.
    TODO this is currently not an UPSERT,
    and non-matching names are just ignored.
*)

val get_entry : plain_category -> string -> (entry, [> R.msg]) result
(** [get_entry category name] retrieves an entry from the [category] tree,
    or an error if no entry of [name] exists.*)

val insert_new_entry : plain_category ->
  entry -> (plain_category, [> R.msg]) result
(** [insert_new_entry category new] inserts [new] into the [category] tree.
    Returns an error if an entry of the same name already exists. *)

val update_entry : plain_category -> entry -> plain_category
(** [update_entry category new] replaces the entry sharing [new]'s name
    in the [category] tree.
    TODO this is currently not an UPSERT,
    and non-matching names are just ignored.
*)

(** {1:slack The functions below are not for public consumption,
             but for unit tests} *)

val json_of_category : category -> Yojson.Basic.json
(** TODO only use for unit tests*)

val json_of_entry : entry -> Yojson.Basic.json

val entry_of_json :
  [> `Assoc of (string * Yojson.Basic.json) list ] ->
  (entry, [> R.msg ]) result
(** TODO this function is used in the library unit tests, but should not be
    exposed. should split up stuff to have an internal module that exposes *
    and a second module that you can expose to everyone else*)

val category_of_json :
  Yojson.Basic.json ->
  (category, [> R.msg ]) result
(** TODO only used in unit tests, see [entry_of_json] *)

(* Commented out:
val json_of_state : state -> [> `Assoc of (string * Yojson.Basic.json) list ]
val json_of_encrypted_data : encrypted_data -> Yojson.Basic.json
val encrypt : key:crypto_key -> Yojson.Basic.json -> encrypted_data
val decrypt :
  key:crypto_key ->
  encrypted_data -> (Yojson.Basic.json, [> R.msg ]) result
val json_of_configuration : (string * string) list -> Yojson.Basic.json
val fold_result :
  ('a -> ('b, 'c) result) -> 'a list -> ('b list, 'c) result
val string_assoc_of_json :
  Yojson.Basic.json ->
  ((string * string) list, [> R.msg ]) result
val configuration_of_json :
  Yojson.Basic.json ->
  ((string * string) list, [> R.msg ]) result
val encrypted_data_of_json :
  Yojson.Basic.json -> (encrypted_data, [> R.msg ]) result
val encrypt_state : key:crypto_key -> state -> encrypted_data
*)
