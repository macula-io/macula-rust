#!/usr/bin/env escript
%% Authorizes, with macula's macula_ucan, the UCANs macula-go minted
%% (scripts/interop/goucan), and compares each verdict with the one the case
%% expects: the reverse of the vectors.
%%
%%   escript erlang_ucan.escript <macula lib dir> <goucan JSON>
%%
%% It prints one line per case and exits 1 if any verdict differs.
main([Lib, File]) ->
    [true = code:add_patha(Dir) || Dir <- filelib:wildcard(filename:join([Lib, "..", "*", "ebin"]))],
    {ok, Bytes} = file:read_file(File),
    Results = [check(C) || C <- json:decode(Bytes)],
    halt(length([bad || false <- Results])).

check(#{<<"name">> := Name, <<"profile">> := P, <<"token">> := Token, <<"proofs">> := Proofs,
        <<"issuer">> := Issuer, <<"caller">> := Caller, <<"now">> := Now, <<"realm">> := Realm,
        <<"procedure">> := Procedure, <<"verdict">> := Want}) ->
    Profile = profile(P),
    Context = #{caller => binary:decode_hex(Caller), profile => Profile, now => Now,
                realm => binary:decode_hex(Realm), procedure => Procedure,
                proofs => maps:from_list([{macula_ucan:proof_id(Pr), Pr} || Pr <- Proofs])},
    Got = verdict(macula_ucan:authorize(Token, {ucan_required, binary:decode_hex(Issuer)}, Context)),
    io:format("~s ~s ~s: ~s~n", [ok_or_fail(Got =:= Want), P, Name, Got]),
    Got =:= Want.

profile(<<"pq_pure">>) -> pq_pure;
profile(<<"pq_hybrid">>) -> pq_hybrid.

verdict({ok, _Claims}) -> <<"ok">>;
verdict({error, Refusal}) -> atom_to_binary(Refusal).

ok_or_fail(true) -> "ok  ";
ok_or_fail(false) -> "FAIL".
