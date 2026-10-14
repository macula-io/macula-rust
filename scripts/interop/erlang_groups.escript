#!/usr/bin/env escript
%% Sealed groups across macula (13.2 on, wire 1.0) and macula-go, through one station, for scripts/interop/groups.sh
%% and scripts/interop/gogroups (DESIGN_E2E_SEALED_PUBSUB.md).
%%
%%   escript erlang_groups.escript <macula lib dir> <host> <port> <station hex> <realm hex> <realm key hex> <profile>
%%           <work dir> distribute <org> <org key id hex> <hold s>
%%   escript erlang_groups.escript ... <work dir> member <prefix> <topic>
%%
%% distribute runs the org's distributor (macula_group_keys, policy required): it prints "node <hex>", waits for
%% <work>/admitted.<hex> (the org's delegation to it is in the DHT), advertises <org>/group_keys_v1 with the org's
%% grant policy and confidential => required, prints "serving" and holds. Its membership admits every caller; its
%% removed set is the node ids listed in <work>/removed, read at each pull.
%%
%% member prints "node <hex>", waits for <work>/grant.<hex> (its org grant), subscribes to <topic> under the group
%% <prefix>, writes <work>/ready.erlang, waits for <work>/ready.go, publishes {text, "from erlang"} sealed under the
%% group, and waits for the peer member's "from <peer>" to arrive opened. It prints each outcome and exits 1 on any
%% other.
%%
%% MACULA_GROUPS_PEER names the peer this runs against, "go" by default: it is the text the peer publishes under the
%% group ("from go", "from rust", ...). macula-rust carries this escript unchanged from macula-go's scripts/interop
%% apart from this variable, so the same peer runs against either SDK.
%% The node identity is a fresh throwaway in a temporary directory.
main([Lib, Host, Port, Station, Realm, RealmKey, Profile, Work, Mode | Args]) ->
    [true = code:add_patha(Dir) || Dir <- filelib:wildcard(filename:join([Lib, "..", "*", "ebin"]))],
    Tmp = string:trim(os:cmd("mktemp -d")),
    P = list_to_atom(Profile),
    ok = application:load(macula),
    ok = application:set_env(macula, crypto_profile, P),
    ok = application:set_env(macula, identity_dir, Tmp),
    ok = application:set_env(macula, kem_advertise, enabled),
    {ok, _} = application:ensure_all_started(macula),
    Seed = #{host => list_to_binary(Host), port => list_to_integer(Port),
             expected_node_id => binary:decode_hex(list_to_binary(Station))},
    R = binary:decode_hex(list_to_binary(Realm)),
    {ok, Pool} = macula:connect([Seed], #{realm_trust => #{R => binary:decode_hex(list_to_binary(RealmKey))}}),
    Self = up(Pool, 300),
    Result = run(Mode, Pool, R, Self, Work, Args),
    os:cmd("rm -rf " ++ Tmp),
    halt(Result).

up(_Pool, 0) -> io:format("no link came up~n"), halt(1);
up(Pool, N) -> healthy(macula:status(Pool), Pool, N).

healthy({ok, #{healthy_links := Healthy, self_node_id := Self}}, _Pool, _N) when Healthy > 0 ->
    io:format("node ~s~n", [hex(Self)]),
    Self;
healthy(_NotYet, Pool, N) ->
    timer:sleep(100),
    up(Pool, N - 1).

hex(Bin) -> binary_to_list(binary:encode_hex(Bin, lowercase)).

run("distribute", Pool, Realm, Self, Work, [Org, OrgKeyId, Hold]) ->
    _ = waited(filename:join(Work, "admitted." ++ hex(Self)), 900),
    Removed = filename:join(Work, "removed"),
    {ok, Distributor} = macula_group_keys:start_link(#{org => list_to_binary(Org), policy => required,
                                                       membership => fun(_Caller) -> ok end,
                                                       removed => fun(Caller) -> removed(Removed, Caller) end}),
    Procedure = <<(list_to_binary(Org))/binary, "/group_keys_v1">>,
    Opts = macula_group_keys:advertise_opts(binary:decode_hex(list_to_binary(OrgKeyId))),
    Advertised = until_ok(fun() -> macula:advertise(Pool, Realm, Procedure, macula_group_keys:handler(Distributor), Opts) end, 150),
    io:format("advertised: ~p~n", [Advertised]),
    ok = Advertised,
    io:format("serving~n"),
    timer:sleep(list_to_integer(Hold) * 1000),
    0;
run("member", Pool, Realm, Self, Work, [Prefix, Topic]) ->
    Token = waited(filename:join(Work, "grant." ++ hex(Self)), 900),
    Opts = #{group => list_to_binary(Prefix), ucan_token => list_to_binary(string:trim(Token))},
    Subscribed = until_ok(fun() -> macula:subscribe(Pool, Realm, list_to_binary(Topic), self(), Opts) end, 150),
    io:format("subscribed: ~p~n", [Subscribed]),
    {ok, _Ref} = Subscribed,
    ok = file:write_file(filename:join(Work, "ready.erlang"), <<>>),
    _ = waited(filename:join(Work, "ready.go"), 900),
    Published = macula:publish(Pool, Realm, list_to_binary(Topic), {text, <<"from erlang">>}, Opts),
    io:format("published: ~p~n", [Published]),
    ok = Published,
    heard(60_000).

%% The peer member's event, opened under the group: `sealed' 1 in its meta.
heard(Ms) ->
    From = <<"from ", (list_to_binary(peer()))/binary>>,
    heard(Ms, From).

heard(Ms, From) ->
    receive
        {macula_event, _Ref, _Topic, {text, From}, #{sealed := 1, seal_key_id := Id}} ->
            io:format("opened from ~s under ~s~n", [peer(), hex(Id)]),
            0;
        {macula_event, _Ref, _Topic, {text, <<"from erlang">>}, _Meta} ->
            heard(Ms);
        {macula_event_unopened, _Ref, _Topic, Meta} ->
            io:format("unopened: ~p~n", [Meta]),
            1;
        Other ->
            io:format("unexpected: ~p~n", [Other]),
            1
    after Ms ->
        io:format("nothing from go~n"),
        1
    end.

%% The peer this runs against, named by MACULA_GROUPS_PEER.
peer() -> os:getenv("MACULA_GROUPS_PEER", "go").

removed(Path, Caller) ->
    listed(file:read_file(Path), hex(Caller)).

listed({ok, Text}, Node) -> lists:member(Node, string:lexemes(binary_to_list(Text), "\n "));
listed({error, _}, _Node) -> false.

%% A file the orchestrating script writes, read once it is there.
waited(Path, 0) -> io:format("no ~s~n", [Path]), halt(1);
waited(Path, N) -> exists(file:read_file(Path), Path, N).

exists({ok, Bin}, _Path, _N) -> binary_to_list(Bin);
exists({error, _}, Path, N) -> timer:sleep(200), waited(Path, N - 1).

%% The distributor's delegation and advertisement reach the DHT in their own time.
until_ok(Fun, 0) -> Fun();
until_ok(Fun, N) -> settled(Fun(), Fun, N).

settled(ok, _Fun, _N) -> ok;
settled({ok, _} = Ok, _Fun, _N) -> Ok;
settled({error, _}, Fun, N) -> timer:sleep(200), until_ok(Fun, N - 1).
