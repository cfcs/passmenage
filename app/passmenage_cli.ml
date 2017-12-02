open Rresult

let file_read name =
  Fpath.of_string name >>= Bos.OS.File.read
  |> R.reword_error (fun _ -> `Msg "Can't open file for reading")

let file_exists name = Fpath.of_string name >>= Bos.OS.File.exists

let file_write ~name data = Fpath.of_string name >>= fun path ->
  Bos.OS.File.write path data

let enter_password () : string =
  Printf.eprintf "Enter password: %!";
  let pw = input_line stdin in
  Logs.debug (fun m -> m "read: %S" pw);
  pw

let enter_password_and_hash () =
  (enter_password ())

let read_db ~db_file =
  file_read db_file >>= fun content ->
  enter_password_and_hash () |> fun pass ->
  Passmenage.unserialize_state ~pass content >>| fun state ->
  (pass, state)

let do_prettyprint _ db_file =
  Logs.app (fun m -> m "%s" db_file) ;
  read_db ~db_file >>= fun (_key , state) ->
  Logs.app (fun m -> m "%a" Passmenage.pp_state state); Ok ()

let do_init _ new_file =
  Logs.app (fun m -> m "Hello, I'm your password manager, I'm going to \
                        initialize a new password file in %S" new_file);
  (file_exists new_file >>= function
    | true -> R.error_msg ("File '"^new_file^"'exists")
    | false -> Ok ()
  ) >>= fun () ->
  let open Passmenage in
  let state = {conf = []; categories = []} in
  enter_password_and_hash () |> fun pass ->
  Passmenage.serialize_state ~pass state >>= fun serialized ->
  file_write ~name:new_file serialized

let do_add _ db_file cat entry_name generate =
  read_db ~db_file >>= fun (pass,state) ->
  let open Passmenage in
  begin match get_category state cat with
     | Error _ ->
       let new_cat = { name = cat ;
                       entries = [] ;
                       encryption_key = None ;
                     } in
       insert_new_category state (Plain_category new_cat) >>| fun new_state ->
       (new_cat, new_state)
    | Ok (Plain_category category) -> Ok (category, state)
    | Ok (Crypt_category c) ->
      Logs.app (fun m -> m "Category %s is encrypted." c.name);
      let pass = enter_password () in
      decrypt_category ~pass c >>| fun c ->
      (c, state)
  end >>= fun (category, state) ->
  begin match get_entry category entry_name with
     | Ok _ -> R.error_msgf "Entry '%s' already exists in category '%s'!"
                 entry_name category.name
     | Error _ -> Ok ()
  end >>= fun () ->
  insert_new_entry category
       { name = entry_name ;
         passphrase = enter_password () ;
         metadata = [];
       }
  >>| (fun cat -> update_category state cat)
  >>| (fun s -> Logs.info (fun m -> m "%a" pp_state s); s)
  >>= serialize_state ~pass
  >>= file_write ~name:db_file

open Cmdliner

let docs = Manpage.s_options
let sdocs = Manpage.s_common_options

let db_file =
  let doc = {| Some doc for db |} in
  Arg.(required & opt (some non_dir_file) None
                & info ["db"] ~docv:"FILE" ~docs ~doc)

let blank_file =
  let doc = {| a non-existant file to write |} in
  Arg.(required & opt (some string) None
                & info ["db"] ~docv:"FILE" ~docs ~doc)

let category =
  let doc = {| A category name |} in
  Arg.(required & opt (some string) None
                & info ["category"] ~docv:"CAT" ~docs ~doc)

let entry =
  let doc = {| A password entry name |} in
  Arg.(required & opt (some string) None
                & info ["entry"] ~docv:"ENTRY" ~docs ~doc)

let generate =
  let doc = {| Automatically generate a password |} in
  Arg.(flag & info ["generate"] ~docv:"ENTRY" ~docs ~doc)


let setup_log =
  let _setup_log (style_renderer:Fmt.style_renderer option) level : unit =
    Fmt_tty.setup_std_outputs ?style_renderer () ;
    Logs.set_level level ;
    Logs.set_reporter (Logs_fmt.reporter ())
  in
  Term.(const _setup_log $ Fmt_cli.style_renderer ~docs:sdocs ()
                         $ Logs_cli.level ~docs:sdocs ())

let cmd_add =
  let doc = {|doc something TODO|} in
  let man =
    [ `S Manpage.s_description ;
      `P {|Add stuff to your password file|}
    ] in
  Term.(term_result (const do_add $ setup_log
                                  $ db_file $ category $ entry $ generate)),
  Term.info "add" ~doc ~sdocs ~exits:Term.default_exits ~man

let cmd_prettyprint =
  let doc = {||} in
  let man = [ `S Manpage.s_description ;
              `P {| yo lo |}
  ] in
  Term.(term_result (const do_prettyprint $ setup_log $ db_file)),
  Term.info "pretty-print" ~doc ~sdocs ~exits:Term.default_exits ~man

let cmd_init =
  let doc = {|Initialize a new password file|} in
  let man = [ `S Manpage.s_description ;
              `P {| yo lo |}
  ] in
  Term.(term_result (const do_init $ setup_log $ blank_file)),
  Term.info "init" ~doc ~sdocs ~exits:Term.default_exits ~man


let cmd_help =
  let doc = {|$(mname) is a command-line interface to the PassMenage password
              manager library.|} in
  let man =
    [ `S Manpage.s_description ;
      `P {| Hello world |};
    ]
  in
  let help _ = `Help (`Pager, None) in
  Term.(ret (const help $ setup_log)),
  Term.info "passmng" ~version:(Manpage.escape "%%VERSION_NUM%%") ~man ~doc
    ~sdocs

let cmds : (unit Cmdliner.Term.t * Cmdliner.Term.info) list =
  [ cmd_prettyprint ; cmd_init ; cmd_add ]

let () =
  Printexc.record_backtrace true;
  Nocrypto_entropy_unix.initialize ();
  Term.(exit @@ eval_choice cmd_help cmds)
