%% macula 12.x's half of scripts/cross-verify-macula.sh: verifies the pq_hybrid
%% composite macula-rust signed, refuses it altered, then signs a message with a
%% pq_hybrid key of its own for macula-rust to verify. The key is generated here
%% and never saved; no macula application is started, so no key file is read.
-module(cross_verify_macula).
-export([main/1]).

main(Dir) ->
    {ok, _} = application:ensure_all_started(crypto),
    ok = application:load(macula),
    {ok, Vsn} = application:get_key(macula, vsn),
    io:format("macula ~s on OTP ~s~n", [Vsn, otp_version()]),
    [Message, Public, Signature] = [read(Dir, "rust_signed", N) || N <- ["m.bin", "pk.bin", "s.bin"]],
    true = macula_node_keys:verify(Message, Signature, Public, pq_hybrid),
    false = macula_node_keys:verify(Message, flipped(Signature, 4627 + 10), Public, pq_hybrid),
    false = macula_node_keys:verify(<<Message/binary, 0>>, Signature, Public, pq_hybrid),
    io:format("rust_signed: verified by macula ~s, refused altered~n", [Vsn]),
    {ok, Key} = macula_node_keys:generate(identity, pq_hybrid),
    Ours = iolist_to_binary(["signed by macula ", Vsn]),
    OurPublic = macula_node_keys:public_key(Key),
    OurSignature = macula_node_keys:sign(Ours, Key),
    true = macula_node_keys:verify(Ours, OurSignature, OurPublic, pq_hybrid),
    ok = filelib:ensure_path(filename:join(Dir, "macula_signed")),
    [ok = file:write_file(filename:join([Dir, "macula_signed", N]), B)
     || {N, B} <- [{"m.bin", Ours}, {"pk.bin", OurPublic}, {"s.bin", OurSignature}]],
    io:format("macula_signed: ~b-byte composite by macula ~s written~n", [byte_size(OurSignature), Vsn]).

read(Dir, Signer, Name) ->
    {ok, Bin} = file:read_file(filename:join([Dir, Signer, Name])),
    Bin.

flipped(Bin, At) ->
    <<Head:At/binary, Byte, Tail/binary>> = Bin,
    <<Head/binary, (Byte bxor 1), Tail/binary>>.

otp_version() ->
    {ok, V} = file:read_file(filename:join([code:root_dir(), "releases", erlang:system_info(otp_release),
                                            "OTP_VERSION"])),
    string:trim(V).
