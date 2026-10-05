#!/usr/bin/env escript
%% Sealed calls and streams across macula 13 and macula-go (E2E seal scheme 1,
%% design §5, amendment A1), through one station, for scripts/interop/gosealed
%% and scripts/interop/tssealed. MACULA_SEALED_PEER names the peer whose texts
%% a call expects ("kept by <peer>", ...): "go" when unset, "ts" for tssealed.
%%
%%   escript erlang_sealed.escript <macula lib dir> <host> <port> <station node_id hex> <realm hex> <profile> serve <hold s>
%%   escript erlang_sealed.escript <macula lib dir> <host> <port> <station node_id hex> <realm hex> <profile> call <provider node_id hex>
%%
%% serve switches kem_advertise on, advertises ~<self>/vault (a call) and
%% ~<self>/watch (a server stream), both confidential => required, publishes
%% their advertisements in the DHT for direct dial, prints "node <hex>" and
%% holds. call calls ~<provider>/vault and opens ~<provider>/watch as macula
%% does by direct dial, sealed to the key the provider's advertisement names,
%% then calls vault at its station with confidential => off (call_station/8),
%% which a required provider must refuse sealed_required. It prints each outcome and exits 1 on any other.
%% The node identity is a fresh throwaway in a temporary directory.
main([Lib, Host, Port, Station, Realm, Profile, Mode | Args]) ->
    [true = code:add_patha(Dir) || Dir <- filelib:wildcard(filename:join([Lib, "..", "*", "ebin"]))],
    Tmp = string:trim(os:cmd("mktemp -d")),
    P = list_to_atom(Profile),
    ok = application:load(macula),
    ok = application:set_env(macula, crypto_profile, P),
    ok = application:set_env(macula, node_identity_path, filename:join(Tmp, "node_identity")),
    ok = application:set_env(macula, kem_advertise, enabled),
    {ok, _} = application:ensure_all_started(macula),
    Seed = #{host => list_to_binary(Host), port => list_to_integer(Port),
             expected_node_id => binary:decode_hex(list_to_binary(Station))},
    {ok, Pool} = macula:connect([Seed], #{}),
    Self = up(Pool, 300),
    R = binary:decode_hex(list_to_binary(Realm)),
    Result = run(Mode, {Pool, Seed}, R, P, Self, Args),
    os:cmd("rm -rf " ++ Tmp),
    halt(Result).

up(_Pool, 0) -> io:format("no link came up~n"), halt(1);
up(Pool, N) -> healthy(macula:status(Pool), Pool, N).

healthy({ok, #{healthy_links := Healthy, self_node_id := Self}}, _Pool, _N) when Healthy > 0 ->
    io:format("node ~s~n", [binary:encode_hex(Self, lowercase)]),
    Self;
healthy(_NotYet, Pool, N) ->
    timer:sleep(100),
    up(Pool, N - 1).

own(Node, Name) ->
    <<"~", (binary:encode_hex(Node, lowercase))/binary, "/", Name/binary>>.

run("serve", {Pool, _Seed}, Realm, Profile, Self, [Hold]) ->
    {ok, Key} = macula_node_keys:node_identity(Profile),
    Vault = own(Self, <<"vault">>),
    Watch = own(Self, <<"watch">>),
    Required = #{confidential => required},
    ok = macula:advertise(Pool, Realm, Vault, fun(_Args) -> {ok, {text, <<"kept by erlang">>}} end, Required),
    ok = macula:advertise_stream(Pool, Realm, Watch, server_stream, fun(Stream, _Args) ->
                                     ok = macula_stream:send(Stream, <<"chunk from erlang">>),
                                     ok = macula_stream:set_reply(Stream, {text, <<"streamed by erlang">>}),
                                     macula_stream:close(Stream)
                                 end, Required),
    ok = macula_direct_dial:publish_advertisement(Pool, Realm, Vault, Key, Required),
    ok = macula_direct_dial:publish_advertisement(Pool, Realm, Watch, Key, Required),
    io:format("serving~n"),
    timer:sleep(list_to_integer(Hold) * 1000),
    0;
run("call", {Pool, Seed}, Realm, _Profile, _Self, [Provider]) ->
    Node = binary:decode_hex(list_to_binary(Provider)),
    Vault = own(Node, <<"vault">>),
    Watch = own(Node, <<"watch">>),
    Called = until_served(fun() -> macula:call(Pool, Realm, Vault, #{n => 1}, 10_000) end, 100),
    io:format("sealed call: ~p~n", [Called]),
    Streamed = streamed(macula:call_stream(Pool, Realm, Watch, #{}, #{mode => server_stream})),
    io:format("sealed stream: ~p~n", [Streamed]),
    %% A clear call is an application's explicit decision, taken only on an
    %% explicit target (macula's call_station/8 with confidential => off):
    %% direct dial seals whenever the advertisement names a key.
    Clear = macula:call_station(Pool, Seed, Node, Realm, Vault, #{n => 1}, 10_000, #{confidential => off}),
    io:format("clear call: ~p~n", [Clear]),
    %% Direct dial with confidential => off: macula 13.0.0 seals it anyway
    %% (it honours off only on an explicit target); 13.0.1 refuses it, as
    %% macula-go's pool does. Strict against 13.0.1 (MACULA_OFF_REFUSED=1).
    Off = macula:call(Pool, Realm, Vault, #{n => 1}, 10_000, #{confidential => off}),
    io:format("off by direct dial: ~p~n", [Off]),
    Peer = list_to_binary(os:getenv("MACULA_SEALED_PEER", "go")),
    report_verdict(os:getenv("MACULA_SEAL_REPORT"), {Pool, Realm, Node, Vault, Watch},
                   off_verdict(os:getenv("MACULA_OFF_REFUSED"), Off, verdict(Peer, Called, Streamed, Clear))).

%% With MACULA_SEAL_REPORT=1 (macula 13.1.0 and later), the seal reports of a sealed call and a sealed stream to the
%% provider: both sealed 1, addressed to it, and naming the same key (DESIGN_E2E_SEAL_REPORT).
report_verdict("1", {Pool, Realm, Node, Vault, Watch}, Verdict) ->
    CallReport = macula:call(Pool, Realm, Vault, #{n => 1}, 10_000, #{report => true}),
    io:format("call report: ~p~n", [CallReport]),
    StreamReport = stream_report(macula:call_stream(Pool, Realm, Watch, #{}, #{mode => server_stream})),
    io:format("stream report: ~p~n", [StreamReport]),
    reported(Node, CallReport, StreamReport, Verdict);
report_verdict(_Off, _Call, Verdict) ->
    Verdict.

stream_report({ok, Stream}) ->
    _ = macula_stream:recv(Stream, 10_000),
    macula:stream_report(Stream);
stream_report(Error) ->
    Error.

reported(Node, {ok, _, #{sealed := 1, provider := Node, seal_key_id := <<Key:64>>}},
         {ok, #{sealed := 1, provider := Node, seal_key_id := <<Key:64>>}}, Verdict) ->
    Verdict;
reported(_Node, _CallReport, _StreamReport, _Verdict) ->
    1.

%% The provider's advertisement reaches the DHT in its own time.
until_served(Call, 0) -> Call();
until_served(Call, N) ->
    case Call() of
        {ok, _} = Ok -> Ok;
        {error, _} -> timer:sleep(200), until_served(Call, N - 1)
    end.

streamed({ok, Stream}) ->
    Chunk = macula_stream:recv(Stream, 10_000),
    Reply = macula_stream:await_reply(Stream, 10_000),
    {Chunk, Reply};
streamed(Error) ->
    Error.

verdict(Peer, {ok, {text, Kept}}, {{chunk, Chunk}, {ok, {text, Streamed}}},
        {error, {call_error, <<"sealed_required">>, _}})
  when Kept =:= <<"kept by ", Peer/binary>>, Chunk =:= <<"chunk from ", Peer/binary>>,
       Streamed =:= <<"streamed by ", Peer/binary>> ->
    0;
verdict(_Peer, _Called, _Streamed, _Clear) ->
    1.

off_verdict("1", {error, {confidentiality, off_needs_explicit_target}}, Verdict) -> Verdict;
off_verdict("1", _Sealed, _Verdict) -> 1;
off_verdict(_NotYet, _Off, Verdict) -> Verdict.
