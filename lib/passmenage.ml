type encrypted_data = { kdf : string ; (* scrypt encryption stuff*)
                        nonce: Cstruct.t ;
                        ciphertext: Cstruct.t ;
                      }

type configuration = (string * string) list

type entry = { name: string ;
               passphrase: string ;
               metadata: (string * string) list
             }

type plain_category = { name : string ;
                        entries : entry list ;
                        encryption_key : string option;
                      }

type crypt_category = { name : string ;
                        encrypted_entries : encrypted_data ;}

type category = Plain_category of plain_category
              | Crypt_category of crypt_category

type state = { conf : configuration ;
               categories: category list ;
             }

let pp_configuration fmt conf =
  Fmt.pf fmt "[@[<v>%a@]]"
    Fmt.(list @@ pair ~sep:(unit ", ") string string) conf

let pp_entry fmt (e:entry) =
  Fmt.pf fmt "{@[<v>name: %S;@ passphrase: %S;@ metadata: [%a]@]}"
    e.name e.passphrase
    Fmt.(list @@ pair ~sep:(unit ", ") string string) e.metadata

let pp_crypto_key fmt (_:string) = Fmt.pf fmt "[ENCRYPTION KEY]"
let pp_category fmt c: unit =
  match c with
  | Crypt_category c ->
    Fmt.pf fmt "{name: %S;@ entries: ENCRYPTED}" c.name
  | Plain_category c ->
    Fmt.pf fmt "{@[<v>name: %S;@ entries: @[<v>%a@]@ key: %a@]}" c.name
      Fmt.(list pp_entry) c.entries
      Fmt.(option ~none:(unit "Empty") pp_crypto_key) c.encryption_key

let pp_state fmt s =
  Fmt.pf fmt "{@[state =@, conf: @[<v>%a@]@,categories: @[<v>%a@]@]}"
    pp_configuration s.conf
    Fmt.(list pp_category) s.categories

open Rresult

let encrypt ~pass json : (encrypted_data, [> R.msg]) result=
  let key_cs = Nocrypto.Rng.generate 32 in
  let key = Nocrypto.Cipher_block.AES.CCM.of_secret ~maclen:16 key_cs in
  Scrypt.encrypt ~maxmem:1_000_000
                 ~maxtime:1.0
                 (Cstruct.to_string key_cs) pass
  |> R.of_option ~none:(fun () -> R.error_msg "Scrypt failed")
  >>| fun kdf ->
  Nocrypto.Cipher_block.AES.CCM.(
    let nonce = Nocrypto.Rng.generate 13
    (* 13 bytes as documented in nocrypto/src/ccm.ml line 28:
         let format nonce adata q t (* mac len *) =
         (* assume n <- [7..13] *)
    *)
    in
    let todo =
      { kdf;
        nonce;
        ciphertext = encrypt ~key ~nonce (Yojson.Basic.to_string json
                                          |> Cstruct.of_string)
    } in
      Logs.debug (fun m -> m "nonce:%a@ @,ciphertext: %a"
                 Cstruct.hexdump_pp todo.nonce
                 Cstruct.hexdump_pp todo.ciphertext
             ); todo
  )

let decrypt ~pass {kdf; nonce;ciphertext}
  : (Yojson.Basic.json, [> R.msg]) result =
  R.of_option ~none:(fun () -> R.error_msg "wrong password")
    (Scrypt.decrypt kdf pass) >>| Cstruct.of_string
  >>| (Nocrypto.Cipher_block.AES.CCM.of_secret ~maclen:16) >>= fun key ->
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
let json_of_encrypted_data {nonce; ciphertext; kdf} : Yojson.Basic.json =
  `Assoc [ "nonce", `String (Cstruct.to_string nonce) ;
           "kdf", `String kdf ;
           "ciphertext", `String (Cstruct.to_string ciphertext) ;
  ]

let name_of_category
  : category -> string = function
  | Crypt_category {name; _} -> name
  | Plain_category {name; entries = _; _} -> name

let json_of_category (cat: category) : Yojson.Basic.json =
  begin match cat with
    | Plain_category {entries; encryption_key; name = _} ->
      let plain_entries = `List (List.map json_of_entry entries) in
      begin match encryption_key with
      | None -> plain_entries
      | Some pass -> json_of_encrypted_data (encrypt ~pass plain_entries |> R.get_ok) (*TODO*)
      end
    | Crypt_category {encrypted_entries; name = _} ->
      json_of_encrypted_data encrypted_entries
  end |> fun serialized ->
  `Assoc [ "name", `String (name_of_category cat) ;
           "entries", serialized ;
         ]

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
  | `Assoc hay ->
    three_assoc_of_json ("nonce","ciphertext","kdf")
      (get_json_str, get_json_str, get_json_str)
      hay
    >>= fun (nonce, ciphertext, kdf) ->
      Ok { ciphertext = Cstruct.of_string ciphertext ;
           nonce = Cstruct.of_string nonce ;
           kdf}
    | json -> R.error_msg (Fmt.strf "invalid encrypted_data json: %a"
                          Yojson.Basic.(pretty_print ~std:true) json)

let category_of_json (json:Yojson.Basic.json)
  : (category, [> R.msg ]) result =
  match json with
    | `Assoc (["name", `String name; "entries", what_entries]
             |["entries", what_entries; "name", `String name]) ->
      begin match what_entries with
        | `List u_entries -> (* it's unencrypted *)
          fold_result entry_of_json u_entries >>| fun entries ->
          Plain_category {name; entries; encryption_key = None}
        | (`Assoc _) as probably_enc ->
          encrypted_data_of_json probably_enc >>| fun encrypted_entries ->
          Crypt_category {name; encrypted_entries}
        | _ -> R.error_msg "entry list in category json is invalid"
      end
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

let encrypt_state ~pass (state : state) =
  (encrypt ~pass (json_of_state state))

let decrypt_state ~pass (enc_state) =
  decrypt ~pass enc_state >>= state_of_json

let serialize_state ~pass (state) =
  encrypt_state ~pass state >>| fun enc_data ->
  json_of_encrypted_data enc_data |> Yojson.Basic.to_string

let unserialize_state ~pass str =
  match Yojson.Basic.from_string str with
  | exception _ -> R.error_msg "invalid json"
  | json ->
    encrypted_data_of_json json >>= decrypt_state ~pass

let encrypt_category ({name;entries; encryption_key})
  : (crypt_category, 'err) result =
  match encryption_key with
  | None -> R.error_msg "encrypt_category: no encryption key provided"
  | Some pass ->
    Ok {name;
        encrypted_entries =
          encrypt ~pass (`List (List.map json_of_entry entries)) |> R.get_ok} (*TODO*)

let decrypt_category ~pass ({name; encrypted_entries}) =
  decrypt ~pass encrypted_entries >>= begin function
    | `List json_ent_lst ->
      fold_result entry_of_json json_ent_lst >>| fun entries ->
      {name; entries; encryption_key = Some pass}
    | _ -> R.error_msg "fucked json after decrypting json"
  end

let generate_password len (alphabet : char list) : (string, [> R.msg]) result=
  begin if len < 0 then R.error_msg "generate_password: length must be positive"
    else Ok () end >>= fun _ ->
  R.ok @@ String.init len (fun _ ->
      Nocrypto.Rng.Int.gen_r 0 (List.length alphabet)
      |> List.nth alphabet)

let insert_new_category {conf;categories = old_cats} new_cat
  : (state, [> R.msg]) result =
  begin if List.exists (fun c ->
      name_of_category c = name_of_category new_cat) old_cats
    then R.error_msg "category already exists"
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
  with Not_found -> R.error_msg "get_category: no such category"

let insert_new_entry ({entries; _} as cat) (entry:entry) =
  if List.exists (fun (e:entry) -> e.name = entry.name) entries
  then R.error_msg "insert_entry: entry already exists"
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
  with Not_found -> R.error_msg "get_entry: no such entry"

let numbers = Array.init 10 (fun i -> Char.chr (0x30+i)) |> Array.to_list
let upper = Array.init 26 (fun i -> Char.chr (0x41+i)) |> Array.to_list
let lower = Array.init 26 (fun i -> Char.chr (0x61+i)) |> Array.to_list
let alphanum = upper @ lower @ numbers
let symbols = ['!'; '#'; '~'; '$'; '%'; '&'; '*'; '-';
               '('; ')'; '_'; '?'; '+'; '/'; '@'; '^'; ]
let all_chars = symbols @ alphanum
