open Rresult
open Passmenage

let () =
  Printexc.record_backtrace true ;
  Nocrypto_entropy_unix.initialize() ;
  Logs.set_reporter @@ Logs_fmt.reporter ~dst:Format.std_formatter () ;
  Logs.(set_level @@ Some Debug)

let entry = {passphrase = "foo"; name = "my pass" ; metadata = ["a","b"]}
let plain_cat = {name="cat name"; entries = [entry];
                 subcategories = [] ; encryption_key = None}
let crypt_cat = {name="cryptocat"; entries = [entry];
                 subcategories = [] ;
                 encryption_key = Some (generate_passphrase 10 all_chars
                                        |> R.get_ok)
                }
let cat = Plain_category plain_cat
let state = {conf = ["conf","conf val"]; categories = [cat]}
let master_key = "a"

(* Define Alcotest modules for value comparison: *)

let a_entry = Alcotest.testable pp_entry (fun (a:entry) b -> a = b)

let a_category = Alcotest.testable pp_category
    (fun (a:category) b -> a = b)

let a_state = Alcotest.testable pp_state
    (fun (a:state) b -> a = b)

let a_msg = Alcotest.testable (fun fmt (`Msg msg) -> Fmt.pf fmt "%s" msg)
    (fun a b -> a = b)

(* Define tests: *)

let test_json_of_entry () =
  Alcotest.(check @@  result a_entry a_msg)
    "json_of_entry |> entry_of_json"
    (Ok entry)
    (json_of_entry entry |> entry_of_json)

let test_json_of_category () =
  Alcotest.(check @@ result a_category a_msg)
    "json_of_category|>category_of_json"
    (Ok cat)
    (json_of_category cat |>  category_of_json)

let test_encrypt_category () =
  Alcotest.(check @@ result a_category a_msg)
    "encrypt_category |> decrypt_category"
    (Ok (Plain_category crypt_cat))
    (encrypt_category crypt_cat
     >>= decrypt_category ~passphrase:(match crypt_cat.encryption_key with
         | Some x -> x | None -> failwith "crypt_cat doesn't have a key")
     >>| fun plain -> Plain_category plain)

let test_serialize_state () =
  let passphrase = generate_passphrase 10 all_chars |> R.get_ok in
  Alcotest.(check @@ result a_state a_msg)
    "serialize_state |> unserialize_state"
    (Ok state)
    (serialize_state ~passphrase state |> unserialize_state ~passphrase)

let tests =
  [
    "core",
    ([ "json_of_entry", `Quick, test_json_of_entry ;
       "json_of_category", `Quick, test_json_of_category ;
       "encrypt_category", `Slow, test_encrypt_category ;
       "serialize_state", `Slow, test_serialize_state ;
     ] : 'a Alcotest.test_case list)
  ]

let () =
  Alcotest.run "passmenage test suite" tests
