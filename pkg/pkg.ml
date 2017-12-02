#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let _mirage = Conf.with_pkg "mirage"
type mirage_backend = Qubes | Unix
let pp_mirage_backend fmt v =
  Format.pp_print_string fmt (match v with Unix -> "Unix" | Qubes -> "Qubes")
let _target : mirage_backend Conf.key =
  Conf.key ~docv:"BACKEND" ~doc:"mirage configure -t" "target"
    ~absent:Unix
  @@ Conf.conv ~docv:"XXX"
    (function "unix" -> Ok Unix
            | "qubes" -> Ok Qubes
            | _ -> R.error_msg "Unsupported Mirage target")
    pp_mirage_backend

(* TODO generate man file, see opam config list | grep man*)

let opams = [Pkg.opam_file ~lint_deps_excluding:(Some ["odoc"]) "opam"]

let build_mirage ctx =
  let target = Conf.value ctx _target  in
  begin match target with
    | Unix ->
      Ok [Pkg.bin "app/passmenage_cli"]
    | _ -> R.error_msg "lolwhat"
  end

let build_unix_gui _ctx = Ok []

let () =
  Pkg.describe "passmenage" ~opams @@ fun c ->
  let shared =
    [ Pkg.mllib ~api:["Passmenage"] "lib/passmenage.mllib" ;
      Pkg.test "test/alcotest_lib" ;
    ]
  in
  match (match Conf.value c _mirage with
      | true -> build_mirage c
      | false -> build_unix_gui c
    ) with
  | Ok lst -> Ok (lst @ shared)
  | err -> err
(*     ; Pkg.mllib ~cond:mirage "mirage/socks.mllib" *)
(*     ; Pkg.mllib ~cond:lwt "src/socks_lwt.mllib" *)
