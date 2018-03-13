type key_slot = { salt : string ;  (* scrypt salt *)
                  nonce : string ; (* symmetric cipher nonce *)
                  ciphertext : string ; (* encrypted master key *)
                }

type encrypted_data = { slots : key_slot list ;
                        nonce: Cstruct.t ;
                        ciphertext: Cstruct.t ;
                      }

type configuration = (string * string) list

type entry = { name: string ;
               passphrase: string ;
               metadata: (string * string) list
             }

type crypt_category = { name : string ;
                        category_ciphertext : encrypted_data ;}

type plain_category = { name : string ;
                        entries : entry list ;
                        subcategories : category list;
                        encryption_key : string option;
                      }
and category = Plain_category of plain_category
             | Crypt_category of crypt_category

type state = { conf : configuration ;
               categories: category list ;
             }

let pp_configuration fmt conf =
  Fmt.pf fmt "[@[<v>%a@]]"
    Fmt.(list @@ pair ~sep:(unit ", ") string string) conf

let pp_entry fmt { name ; passphrase ; metadata } =
  Fmt.pf fmt "{@[<v>\"name\": %S,@ \"passphrase\": %S,@ \"metadata\": [%a]@]}"
    name passphrase
    Fmt.(list @@ pair ~sep:(unit ", ") string string) metadata

let pp_crypto_key fmt (_:string) = Fmt.pf fmt "[ENCRYPTION KEY]"

let rec pp_category fmt c : unit =
  match c with
  | Crypt_category { name ; category_ciphertext = _ } ->
    Fmt.pf fmt "{\"name\": %S,@ \"entries\": \"ENCRYPTED\"}" name
  | Plain_category { name ; entries; subcategories ; encryption_key } ->
    Fmt.pf fmt "{@[<v>\"name\": %S,\
                @ \"entries\": [@[<v>%a@]],\
                @ \"key\": %a,\
                @ \"subcategories\": [@[<v>%a@]]@]}"
      name
      Fmt.(list ~sep:(unit ",@,") pp_entry) entries
      Fmt.(option ~none:(unit "\"\"") pp_crypto_key) encryption_key
      Fmt.(list pp_category) subcategories

let pp_state fmt s =
  Fmt.pf fmt "{@[\"configuration\": @[<v>%a@],@,\"categories\": [@[<v>%a@]]@]}"
    pp_configuration s.conf
    Fmt.(list pp_category) s.categories

open Rresult

let hash ~salt ~passphrase =
  Scrypt_kdf.scrypt_kdf ~salt
    ~password:(Cstruct.of_string passphrase)
    ~dk_len:32_l (* <-- output len, in bytes *)
    (* how to use scrypt: https://stackoverflow.com/a/30308723 *)
    (* memory consumption: ~128 bytes * N_cost * r_blockSizeFactor *)
    (* memory consumed: 128 * 16 KB * 9 = 18.5 MB. *)
    (* n is the iteration count, and p is the amount of times you run
       the algorithm*)
    (* This takes ~7s on my machine:*)
    ~n:(16384) ~r:9 ~p:6

let encrypt_data ~key plaintext =
  Nocrypto.Cipher_block.AES.CCM.(
    let nonce = Nocrypto.Rng.generate 13 in
    (* ^-- 13 bytes as documented in nocrypto/src/ccm.ml line 28:
         let format nonce adata q t (* mac len *) =
         (* assume n <- [7..13] *)
    *)
    nonce, encrypt ~key ~nonce plaintext )

let decrypt_data ~nonce ~key ciphertext =
  Nocrypto.Cipher_block.AES.CCM.(
    decrypt ~nonce ~key ciphertext
  ) |> R.of_option
    ~none:(fun () ->
        R.error_msgf "Decryption failed: %a" Cstruct.hexdump_pp ciphertext)

let encrypt_slot ~passphrase master_key_plaintext : key_slot =
  let salt = Nocrypto.Rng.generate 16 in
  let key = hash ~passphrase ~salt
            |> Nocrypto.Cipher_block.AES.CCM.of_secret ~maclen:16 in
  let nonce, ciphertext = encrypt_data ~key master_key_plaintext in
  { salt       = Cstruct.to_string salt ;
    nonce      = Cstruct.to_string nonce ;
    ciphertext = Cstruct.to_string ciphertext }

let decrypt_slot ~passphrase ~salt ~nonce ~ciphertext =
  let key = hash ~passphrase ~salt:(Cstruct.of_string salt)
            |> Nocrypto.Cipher_block.AES.CCM.of_secret ~maclen:16 in
  let nonce  = Cstruct.of_string nonce in
  let ciphertext = Cstruct.of_string ciphertext in
  decrypt_data ~nonce ~key ciphertext

let encrypt ~passphrase json : encrypted_data =
  let master_key = Nocrypto.Rng.generate 32 in
  let slot = encrypt_slot ~passphrase master_key in
  Nocrypto.Cipher_block.AES.CCM.(
    let nonce, ciphertext =
      encrypt_data ~key:(of_secret ~maclen:16 master_key)
        (Yojson.Basic.to_string json
         |> Cstruct.of_string) in
    Logs.debug (fun m -> m "nonce:%a@ @,ciphertext: %a"
                   Cstruct.hexdump_pp nonce
                   Cstruct.hexdump_pp ciphertext
               );
    { slots = [ slot ] ;
      nonce;
      ciphertext
    }
  )

let decrypt ~passphrase {slots; nonce; ciphertext}
  : (Yojson.Basic.json, [> R.msg]) result =
  ( let { salt ; nonce ; ciphertext } = List.hd slots in (* TODO *)
    decrypt_slot ~salt ~nonce ~ciphertext ~passphrase
  ) >>| (Nocrypto.Cipher_block.AES.CCM.of_secret ~maclen:16) >>= fun key ->
  Logs.debug (fun m -> m "decrypt: got a slot");
  match Nocrypto.Cipher_block.AES.CCM.decrypt ~key ~nonce ciphertext with
  | None -> R.error_msg "Unable to decrypt"
  | Some plaintext_cs ->
    begin match Cstruct.to_string plaintext_cs
                |> Yojson.Basic.from_string with
    | json -> Ok json
    | exception _ -> (*this piece of shit does not document its exceptions*)
      R.error_msg "Unable to deserialize json for some reason \
                   (fuck the yojsonmodule)"
    end

let json_of_configuration conf : Yojson.Basic.json =
  `Assoc (List.map (fun (k,v) -> k, `String v) conf)

let json_of_entry {passphrase; name; metadata} : Yojson.Basic.json =
  `Assoc [ "name", `String name ;
           "passphrase", `String passphrase;
           "metadata", `Assoc (List.map (fun (k,v) -> k, `String v) metadata);
         ]

let json_of_key_slot { salt; nonce ; ciphertext } =
  `Assoc [ "salt", `String salt ;
           "nonce", `String nonce ;
           "ciphertext", `String ciphertext ;
         ]

let json_of_encrypted_data {nonce; ciphertext; slots} : Yojson.Basic.json =
  `Assoc [ "nonce", `String (Cstruct.to_string nonce) ;
           "slots", `List (List.map json_of_key_slot slots) ;
           "ciphertext", `String (Cstruct.to_string ciphertext) ;
  ]

let name_of_category
  : category -> string = function
  | Crypt_category {name; _} -> name
  | Plain_category {name; entries = _; _} -> name

let rec json_of_category (cat: category) : Yojson.Basic.json =
  let wrap_encrypted v =
    ["category_ciphertext", v]
  in
  begin match cat with
    | Plain_category {entries; subcategories; encryption_key; name = _} ->
      let plain =
        let plain_entries = `List (List.map json_of_entry entries) in
        let plain_subcategories = List.map json_of_category subcategories in
        [ "entries", plain_entries ;
          "subcategories", `List plain_subcategories]
      in
      begin match encryption_key with
        | None -> plain
        | Some passphrase ->
          json_of_encrypted_data (encrypt ~passphrase (`Assoc plain))
          |> wrap_encrypted
      end
    | Crypt_category {category_ciphertext; name = _ } ->
      wrap_encrypted (json_of_encrypted_data category_ciphertext)
  end |> fun serialized ->
  `Assoc (("name", `String (name_of_category cat))::serialized)

let fold_result f lst =
  let rec loop acc = function
    | [] -> Ok (List.rev acc)
    | hd::tl -> f hd >>= fun applied -> loop (applied::acc) tl
  in loop [] lst

let string_assoc_of_json (json:Yojson.Basic.json)
  : ((string * string) list, [>]) result =
  begin match json with
    | `Assoc lst ->
      fold_result
        (function | (k,`String v) -> Ok (k,v)
                  | _ -> R.error_msg "invalid configuration")
        lst
    | _ -> R.error_msg "invalid configuration"
  end

let configuration_of_json json = string_assoc_of_json json

let three_assoc_of_json (k1,k2,k3) (f1,f2,f3)hay =
  let rec loop acc hay =
    begin match acc, hay with
      | (None, p, m), (k, v)::tl when k = k1 ->
        f1 v >>= fun v1 -> loop (Some v1, p, m) tl
      | (n, None, m), (k, v)::tl when k = k2 ->
        f2 v >>= fun v2 -> loop (n, Some v2, m) tl
      | (n, p, None), (k, v)::tl when k = k3 ->
        f3 v >>= fun v3 -> loop (n, p, Some v3) tl
      | (Some v1, Some v2, Some v3), [] -> Ok (v1,v2,v3)
      | _ , _ -> R.error_msg "invalid entry json"
    end
  in loop (None,None,None) hay

let get_json_str = function
  | `String s -> Ok s
  | _ -> R.error_msg "json must be str" (* TODO pp error?*)

let get_json_list = function
  | `List lst -> Ok lst
  | _ -> R.error_msg "json must be list" (* TODO pp error?*)

let entry_of_json json =
  begin match json with
    | `Assoc lst ->
      three_assoc_of_json ("name","passphrase","metadata")
        (get_json_str, get_json_str, string_assoc_of_json)
        lst
      >>| fun (name, passphrase, metadata) ->
      { name; passphrase; metadata }
    | _ -> R.error_msg "invalid entry json"
  end

let encrypted_data_of_json
  : Yojson.Basic.json -> (encrypted_data, [> R.msg ])result = function
  | `Assoc dict ->
    three_assoc_of_json ("nonce","ciphertext","slots")
      (get_json_str, get_json_str, get_json_list)
      dict
    >>= fun (nonce, ciphertext, slots ) ->
    let json_of_slot = function
      | `Assoc dict ->
        three_assoc_of_json ("salt", "nonce", "ciphertext")
          (get_json_str, get_json_str, get_json_str)
          dict >>| fun (salt,nonce,ciphertext) ->
        {salt ; nonce; ciphertext}
      | json -> R.error_msgf "Invalid slot: %a"
               Yojson.Basic.(pretty_print ~std:true) json
    in
    fold_result json_of_slot slots
      >>= fun slots ->
    Ok { ciphertext = Cstruct.of_string ciphertext ;
         nonce = Cstruct.of_string nonce ;
         slots }
  | json -> R.error_msg (Fmt.strf "invalid encrypted_data json: %a"
                           Yojson.Basic.(pretty_print ~std:true) json)

let rec category_of_json (json:Yojson.Basic.json)
  : (category, [> R.msg ]) result =
  match json with
  | `Assoc ( ["name", `String name ; "category_ciphertext", enc_data]
           | ["category_ciphertext", enc_data ; "name", `String name]) ->
    encrypted_data_of_json enc_data >>| fun category_ciphertext ->
    Crypt_category {name; category_ciphertext}
  | `Assoc member_assoc -> (* it's unencrypted *)
    three_assoc_of_json ("name", "entries", "subcategories")
      (get_json_str, get_json_list, get_json_list) member_assoc
    |> R.reword_error_msg (fun _ -> `Msg "malformed category json")
    >>= fun (name, entries, subcategories) ->
    fold_result category_of_json subcategories >>= fun subcategories ->
    fold_result entry_of_json entries >>| fun entries ->
    Plain_category { name ; entries; encryption_key = None;
                     subcategories ; }
  | _ -> R.error_msg "invalid category json"

let json_of_state {conf; categories} =
  `Assoc [ "configuration", json_of_configuration conf ;
           "categories", `List (List.map json_of_category categories) ;
  ]

let state_of_json json : (state, [> R.msg] ) result =
  match json with
  | `Assoc ( ["configuration", conf_json ; "categories", `List cat_json]
           | ["categories", `List cat_json ; "configuration", conf_json])  ->
     configuration_of_json conf_json >>= fun conf ->
    fold_result category_of_json cat_json >>| fun categories ->
    {categories; conf}
  | _ -> R.error_msg "invalid state json"

let encrypt_state ~passphrase (state : state) =
  encrypt ~passphrase (json_of_state state)

let decrypt_state ~passphrase (enc_state) =
  decrypt ~passphrase enc_state >>= state_of_json

let serialize_state ~passphrase (state) =
  encrypt_state ~passphrase state
  |> json_of_encrypted_data
  |> Yojson.Basic.to_string

let unserialize_state ~passphrase str =
  match Yojson.Basic.from_string str with
  | exception _ -> R.error_msg "invalid json"
  | json ->
    encrypted_data_of_json json >>= decrypt_state ~passphrase

let encrypt_category ({name; entries; subcategories; encryption_key})
  : (crypt_category, 'err) result =
  match encryption_key with
  | None -> R.error_msg "encrypt_category: no encryption key provided"
  | Some passphrase ->
    Ok {name ;
        category_ciphertext =
          encrypt ~passphrase
            (`Assoc
               ["entries", `List (List.map json_of_entry entries) ;
                "subcategories", `List (List.map json_of_category subcategories)
               ])
       }

let decrypt_category ~passphrase {name; category_ciphertext} =
  decrypt ~passphrase category_ciphertext >>= begin function
    | `Assoc ["entries", `List json_ent_lst;
              "subcategories", `List json_subcat_lst ] ->
      fold_result entry_of_json json_ent_lst >>= fun entries ->
      fold_result category_of_json json_subcat_lst >>| fun subcategories ->
      {name; entries; encryption_key = Some passphrase; subcategories }
    | json -> R.error_msgf "fucked json after decrypting json: %a"
                (Yojson.Basic.pretty_print ~std:true) json
  end

let generate_passphrase len (alphabet : char list) : (string, [> R.msg]) result=
  begin if len < 0
    then R.error_msg "generate_passphrase: length must be positive"
    else Ok () end >>= fun _ ->
  R.ok @@ String.init len (fun _ ->
      Nocrypto.Rng.Int.gen_r 0 (List.length alphabet)
      |> List.nth alphabet)

let insert_new_category {conf;categories = old_cats} new_cat
  : (state, [> R.msg]) result =
  begin if List.exists (fun c ->
      name_of_category c = name_of_category new_cat) old_cats
    then R.error_msgf "category %S already exists" (name_of_category new_cat)
    else R.ok (new_cat :: old_cats)
  end >>| fun categories -> {conf; categories}

let update_category {conf; categories = old_cats} (new_cat:plain_category) =
  {conf;
   categories = List.map (function
       | Plain_category c when c.name = new_cat.name ->
         Plain_category new_cat
       | ( Crypt_category _
         | Plain_category _) as old -> old
     ) old_cats
  }

let get_category {categories; conf = _} cat_name  =
  try List.find (fun c -> name_of_category c = cat_name) categories |> R.ok
  with Not_found -> R.error_msgf "get_category: no such category: %S" cat_name

let insert_new_entry ({entries; _} as cat) (entry:entry) =
  if List.exists (fun (e:entry) -> e.name = entry.name) entries
  then R.error_msgf "insert_entry: entry %S already exists" entry.name
  else
    Ok { cat with
         entries = entry::entries
       }

let update_entry ({entries;_} as cat) (entry:entry) =
  { cat with
    entries = List.map (function
        | old when old.name = entry.name -> entry
        | (old:entry) -> old) entries
  }

let get_entry {entries; _} entry_name =
  try List.find (fun (e:entry) -> e.name = entry_name) entries |> R.ok
  with Not_found -> R.error_msgf "get_entry: no such entry: %S" entry_name

let decimals = Array.init 10 (fun i -> Char.chr (0x30+i)) |> Array.to_list
let upper = Array.init 26 (fun i -> Char.chr (0x41+i)) |> Array.to_list
let lower = Array.init 26 (fun i -> Char.chr (0x61+i)) |> Array.to_list
let alphanum = upper @ lower @ decimals
let symbols = ['!'; '#'; '~'; '$'; '%'; '&'; '*'; '-';
               '('; ')'; '_'; '?'; '+'; '/'; '@'; '^'; ]
let all_chars = symbols @ alphanum
