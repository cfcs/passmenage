open Rresult

let file_read name =
  Bos.OS.File.read name
  |> R.reword_error (fun _ -> R.msgf "Can't open %a for reading" Fpath.pp name)

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

let do_prettyprint _ (db_file:Fpath.t) =
  read_db ~db_file >>= fun (_key , state) ->
  Logs.app (fun m -> m "%a" Passmenage.pp_state state); Ok ()

let do_init _ (new_file:Fpath.t) =
  Logs.app (fun m -> m "Hello, I'm your password manager, I'm going to \
                        initialize a new password file in %a"
               Fpath.pp new_file);
  (Bos.OS.File.exists new_file >>= function
    | true -> R.error_msgf "File %a exists" Fpath.pp new_file
    | false -> Ok ()
  ) >>= fun () ->
  let open Passmenage in
  let state = {conf = []; categories = []} in
  enter_password_confirm () >>= fun pass ->
  Passmenage.serialize_state ~pass state >>= fun serialized ->
  Bos.OS.File.write new_file serialized

let put_password_in_xclip pw =
  (* has xclip, make it delete after first paste *)
  let pw_as_pipe = Bos.OS.Cmd.in_string pw in
  Bos.(pw_as_pipe |> OS.Cmd.run_in
       @@ Cmd.of_list ["xclip"; "-i"; "-l"; "1"; "-selection"; "clipboard"])

let put_password_in_xsel pw =
  let pw_as_pipe = Bos.OS.Cmd.in_string pw in
  let timeout = 17 in
  Printf.eprintf
    "Waiting for %d seconds, then clearing your password.\n%!" timeout ;
  Bos.(pw_as_pipe |> OS.Cmd.run_in
       @@ Cmd.of_list ["xsel";"-ibt";
                       (string_of_int timeout) ^ "000"])
  >>| (fun () ->
      (* TODO: since -t in xsel is broken, we implement the equivalen
              behaviour manually in here. very nice. thanks guys. *)
      Unix.sleep timeout ;
      Bos.(OS.Cmd.run_out @@ Cmd.of_list ["xsel"; "-b"])
      (* ^-- retrieve clipboard*)
    ) >>= Bos.OS.Cmd.to_string >>= fun this_the_same_pw ->
  if this_the_same_pw = pw then (* safe to clear it: *)
    Bos.(OS.Cmd.run @@ Cmd.of_list ["xsel"; "-bd"])
  else (* the user overwrote their clipboard; no action taken.*)
    Ok ()

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
  match clipboard_xsel with
    | true -> Bos.OS.Cmd.exists @@ Bos.Cmd.of_list ["xclip"]
      >>= (function | true ->  put_password_in_xclip entry.passphrase
                    | false -> put_password_in_xsel  entry.passphrase)
    | false ->
      Logs.app (fun m -> m "%s" entry.passphrase) |> R.ok

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
   else enter_password_confirm ~prompt:"Enter password to store" ()
  ) >>= fun passphrase ->
  insert_new_entry category
       { name = entry_name ;
         passphrase ;
         metadata = [];
       }
  >>| (fun cat -> update_category state cat)
  >>| (fun s -> Logs.info (fun m -> m "%a" pp_state s); s)
  >>= serialize_state ~pass
  >>= Bos.OS.File.write db_file

open Cmdliner

let docs = Manpage.s_options
let sdocs = Manpage.s_common_options

let default_db_file = Fpath.append
    (Bos.OS.Dir.user () |> R.get_ok)
    (Fpath.of_string ".config/passmenage.store" |> R.get_ok)

let fpath_conv : Fpath.t Cmdliner.Arg.conv =
  (fun x -> match Fpath.of_string x with
     | Ok a -> `Ok a
     | Error (`Msg m) -> `Error m
  ), Fpath.pp

let db_file =
  let doc = {|The path to the password database file|} in
  Arg.(value & opt fpath_conv default_db_file
       & info ["db"] ~docv:"FILE" ~docs ~doc)

let blank_file =
  let doc = {| A non-existant file to write |} in
  Arg.(value & opt fpath_conv default_db_file
             & info ["db"] ~docv:"FILE" ~docs ~doc)

let (category : string  Cmdliner.Term.t),
     opt_category (* : string Cmdliner.Term.t*) =
  let doc = {| A category name |} in
  Arg.(
    required & pos 0 (some string) None & info [] ~docv:"CATEGORY" ~docs ~doc,
    value & pos 0 (some string) None & info [] ~docv:"CATEGORY" ~docs ~doc)

let entry, opt_entry =
  let doc = {| A password entry name |} in
  Arg.(
    required & pos 1 (some string) None & info [] ~docv:"ENTRY-NAME" ~docs ~doc,
    value & pos 1 (some string) None & info [] ~docv:"ENTRY-NAME" ~docs ~doc)

let clipboard : bool Cmdliner.Term.t =
  let doc = {|Place the passphrase in clipboard using `xclip` or `xsel`.
              With `xclip` the passphrase is erased after the first paste.
              With `xsel` the passphrase is erased after a 17 second timeout.|}
  in
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
    [ `S Manpage.s_description ;
      `P {|Add a password entry to your password file.|} ;
    ] in
  Term.(term_result
          (const do_add $ setup_log
           $ db_file $ category $ entry $ generate $ charset)),
  Term.info "add" ~doc ~sdocs ~exits:Term.default_exits ~man

let cmd_prettyprint =
  let doc = {|Pretty-print the state (INCLUDING PASSWORDS) |} in
  let man =
    [ `S Manpage.s_description ;
      `P {|Pretty-print the entire state (including passwords) in JSON.
           This can be used to export your passwords.|}
  ] in
  Term.(term_result (const do_prettyprint $ setup_log $ db_file)),
  Term.info "pretty-print" ~doc ~sdocs ~exits:Term.default_exits ~man

let cmd_init =
  let doc = {|Initialize a new password file|} in
  let man =
    [ `S Manpage.s_description ;
      `P (Fmt.strf {|
           The optional argument $(i,--db) may be used to override the default
           location which is %a|} Fpath.pp default_db_file)
    ]
  in
  Term.(term_result (const do_init $ setup_log $ blank_file)),
  Term.info "init" ~doc ~sdocs ~exits:Term.default_exits ~man

let cmd_get =
  let doc = {|Get an entry from the password file.|} in
  let man = [ `S Manpage.s_description ;
              `P {|Prints a password to $(i,STDOUT) if the optional argument
                   $(i,--clipboard) is not given.|}
  ] in
  Term.(term_result (const do_get $ setup_log
                     $ db_file $ category $ entry
                     $ clipboard)),
  Term.info "get" ~doc ~sdocs ~exits:Term.default_exits ~man

let cmd_list =
  let doc = {|List categories, or entries in a specific category|} in
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
