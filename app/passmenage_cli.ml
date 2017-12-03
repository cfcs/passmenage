open Rresult

let file_read name =
  Fpath.of_string name >>= Bos.OS.File.read
  |> R.reword_error (fun _ -> `Msg "Can't open file for reading")

let file_exists name = Fpath.of_string name >>= Bos.OS.File.exists

let file_write ~name data = Fpath.of_string name >>= fun path ->
  Bos.OS.File.write path data

let prompt_password ?prompt () : string =
  if Unix.isatty (Unix.descr_of_in_channel stdin)
  then Printf.eprintf "%s: %!" (match prompt with Some x -> x
                                                | None -> "Enter password") ;
  if Unix.isatty (Unix.descr_of_out_channel stdout)
  then begin
    let open Unix in
    let attr = tcgetattr stdout in
    tcsetattr stdout TCSAFLUSH
      {attr with
       c_echo = false; c_echonl = true; c_icanon=true } ;
    let pw = input_line Pervasives.stdin in
    tcsetattr stdout TCSAFLUSH {attr with c_echo = true} ;
    pw
  end else begin
    input_line stdin
  end |> fun pw ->
  Logs.debug (fun m -> m "read: %S" pw);
  pw

let enter_password_confirm ?prompt () : (string, [> R.msg]) result =
  let pw = prompt_password ?prompt () in
  let confirm = prompt_password ~prompt:"Confirm" () in
  if pw = confirm
  then Ok pw
  else R.error_msg "Password mismatch"

let read_db ~db_file =
  file_read db_file >>= fun content ->
  prompt_password ~prompt:"Enter password for state file" () |> fun pass ->
  Passmenage.unserialize_state ~pass content >>| fun state ->
  (pass, state)

let do_prettyprint _ db_file =
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
  enter_password_confirm () >>= fun pass ->
  Passmenage.serialize_state ~pass state >>= fun serialized ->
  file_write ~name:new_file serialized

let do_get _ db_file cat entry_name clipboard_xsel =
  read_db ~db_file >>= fun (_, state) ->
  let open Passmenage in
  get_category state cat >>=
  (function
    | Plain_category c -> Ok c
    | Crypt_category c -> let pass = prompt_password () in
                          decrypt_category ~pass c
  ) >>= fun cat ->
  get_entry cat entry_name >>= fun entry ->
  begin match clipboard_xsel with
    | true ->
      let timeout = 10 in
      Printf.eprintf "Waiting for %d seconds, then clearing your password.\n%!"
        timeout ;
      Bos.(OS.Cmd.run_in (Cmd.of_list ["xsel";"-ibt";
                                       (string_of_int timeout) ^ "000"])
           @@ OS.Cmd.in_string entry.passphrase)
      >>| (fun () ->
          (* TODO: since -t in xsel is broken, we implement the equivalent
                  behaviour manually in here. very nice. thanks guys. *)
        Unix.sleep timeout ;
        Bos.(OS.Cmd.run_out @@ Cmd.of_list ["xsel"; "-b"])
        (* ^-- retrieve clipboard*)
        ) >>= Bos.OS.Cmd.to_string >>= fun this_the_same_pw ->
      if this_the_same_pw = entry.passphrase then (* safe to clear it: *)
          Bos.(OS.Cmd.run @@ Cmd.of_list ["xsel"; "-bd"])
      else (* the user overwrote their clipboard; no action taken.*)
        Ok ()
    | false ->
      Logs.app (fun m -> m "%s" entry.passphrase) |> R.ok
  end

let do_list _ db_file opt_cat =
  read_db ~db_file >>= fun (_, state) ->
  let open Passmenage in
  begin match opt_cat with
    | None ->
      Logs.app (fun m -> m "Categories:   @[<v>%a@]"
                Fmt.(list ~sep:(unit "@,") string)
                 @@ List.map (fun c -> name_of_category c) state.categories) ;
      Ok ()
    | Some cat_name ->
      get_category state cat_name
      >>= ( function
          | Crypt_category c -> let pass = prompt_password () in
                                decrypt_category ~pass c
          | Plain_category c -> Ok c
        ) >>| fun (cat : plain_category) ->
      Logs.app (fun m -> m "Category \"%s\":    @[<v>%a@]" cat.name
                   Fmt.(list @@ pair ~sep:(unit " -> ") string
                                 @@ Fmt.vbox
                                 @@ list @@ pair ~sep:(unit ": ") string string)
                   (List.map (fun (x:entry) -> x.name, x.metadata)
                      cat.entries))
  end

let do_add _ db_file cat entry_name generate charset =
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
      let pass = prompt_password
          ~prompt:("Enter password for category '" ^ c.name ^ "'")
          () in
      decrypt_category ~pass c >>| fun c ->
      (c, state)
  end >>= fun (category, state) ->
  begin match get_entry category entry_name with
     | Ok _ -> R.error_msgf "Entry '%s' already exists in category '%s'!"
                 entry_name category.name
     | Error _ -> Ok ()
  end >>= fun () ->
  (if generate
   then generate_password 16
       (match charset with
        | Some sets -> List.(flatten sets |> sort_uniq compare)
        | None -> alphanum)
   else enter_password_confirm ~prompt:"Enter new password" ()
  ) >>= fun passphrase ->
  insert_new_entry category
       { name = entry_name ;
         passphrase ;
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

let category, opt_category =
  let doc = {| A category name |} in
  let shared = Arg.(opt (some string) None
                    & info ["category"] ~docv:"CAT" ~docs ~doc)
  in Arg.(required shared, value shared)

let entry, opt_entry =
  let doc = {| A password entry name |} in
  let shared = Arg.(opt (some string) None
                    & info ["entry"] ~docv:"ENTRY" ~docs ~doc)
  in Arg.(required shared, value shared)

let clipboard : bool Cmdliner.Term.t =
  let doc = {|Place the password in clipboard using `xsel`|} in
  Arg.(value & flag & info ["clipboard"] ~docv:"WATT" ~docs ~doc)

let generate : bool Cmdliner.Term.t =
  let doc = {| Automatically generate a password |} in
  Arg.(value & flag & info ["generate"] ~docv:"ENTRY" ~docs ~doc)

let charsets, charset_enum =
  let charsets = Passmenage.["lower", lower ;
                             "upper", upper ;
                             "decimal", decimals ;
                             "alphanum", alphanum ;
                             "symbols", symbols ;
                             "all", all_chars ;
                            ]
  in charsets, Arg.enum charsets
let charset : char list list option Cmdliner.Term.t =
  let doc = {|Comma-separated list of character sets to choose from.

              fucking cmdliner, how does that work?|} in
  let chars = Fmt.strf "@[<v>%a@]"
      Fmt.(list ~sep:(unit "\n")
           @@ pair ~sep:(unit ": \t") string
              @@ list char) charsets in
  let doc = doc ^ chars in
  Arg.(value & opt (some @@ list charset_enum) None
             & info ["charset"] ~docv:"CHARSET" ~docs ~doc)

let setup_log =
  let _setup_log (style_renderer:Fmt.style_renderer option) level : unit =
    Fmt_tty.setup_std_outputs ?style_renderer () ;
    Logs.set_level level ;
    Logs.set_reporter (Logs_fmt.reporter ())
  in
  Term.(const _setup_log $ Fmt_cli.style_renderer ~docs:sdocs ()
                         $ Logs_cli.level ~docs:sdocs ())

let cmd_add =
  let doc = {|Add an entry to a category.|} in
  let man =
    [ `S Manpage.s_synopsis ;
      `P {|$(tname) --db $(i,FILE) --cat $(i,CATEGORY) --ent $(i,ENTRY) \
          [$(i,OPTIONS)] |} ;
      `S Manpage.s_description ;
      `P {|Add stuff to your password file|} ;

    ] in
  Term.(term_result
          (const do_add $ setup_log
           $ db_file $ category $ entry $ generate $ charset)),
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

let cmd_get =
  let doc = {|Get an entry from the password file.|} in
  let man = [ `S Manpage.s_description ;
              `P {| yo lo |}
  ] in
  Term.(term_result (const do_get $ setup_log
                     $ db_file $ category $ entry
                     $ clipboard)),
  Term.info "get" ~doc ~sdocs ~exits:Term.default_exits ~man

let cmd_list =
  let doc = {||} in
  let man = [] in
  Term.(term_result (const do_list $ setup_log
                                   $ db_file $ opt_category)),
  Term.info "list" ~doc ~docs ~exits:Term.default_exits ~man

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
  [ cmd_prettyprint ; cmd_init ; cmd_add ; cmd_get ; cmd_list ]

let () =
  Printexc.record_backtrace true;
  Nocrypto_entropy_unix.initialize ();
  Term.(exit @@ eval_choice cmd_help cmds)
