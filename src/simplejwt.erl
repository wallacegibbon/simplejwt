%% for now, only HS256(HMAC+SHA256) is supported.

-module(simplejwt).

-export([encode/3, encode/4, decode/2]).

decode(Key, Token) ->
    try
	{ok, maps:without([<<"exp">>], parse_token(Key, Token))}
    catch
	error:_ ->
	    invalid_token
    end.

parse_token(Key, Token) ->
    [Header, Body, Sign] = split_token(Token),
    #{<<"alg">> := Alg} = jsone:decode(base64url:decode(Header)),
    true = validate_sign(Alg, Key, Header, Body, Sign),
    Data = jsone:decode(base64url:decode(Body)),
    true = not_expired(Data),
    Data.

not_expired(#{<<"exp">> := Exp}) ->
    Exp > epoch().

encode(Key, Data, ExpirationSeconds) ->
    encode(<<"HS256">>, Key, Data, ExpirationSeconds).

encode(Alg, Key, Data, ExpirationSeconds) ->
    try
	{ok, make_token(Alg, Key, Data, ExpirationSeconds)}
    catch
	error:_ ->
	    failed
    end.

make_token(Alg, Key, Data, ExpirationSeconds) ->
    ExpireTime = ExpirationSeconds + epoch(),
    Body = base64url:encode(jsone:encode(Data#{<<"exp">> => ExpireTime})),
    Header = base64url:encode(jsone:encode(header(Alg))),
    Payload = <<Header/binary, ".", Body/binary>>,
    Sign = sign(Alg, Payload, Key),
    <<Payload/binary, ".", Sign/binary>>.


-ifdef(TEST).

-include_lib("eunit/include/eunit.hrl").

-define(TEST_KEY, "hello, this is a test").

encode_test() ->
    Data = #{<<"a">> => #{<<"b">> => 2}},
    {ok, Token} = encode(?TEST_KEY, Data, 60),
    %?debugFmt("token ~p~n", [Token]),
    {ok, D1} = decode(?TEST_KEY, Token),
    %?debugFmt("decoded ~p~n", [D1]),
    ?assert(D1 =:= Data).

sleep(Seconds) ->
    receive after Seconds * 1000 -> ok end.

expire_test() ->
    Data = #{<<"a">> => #{<<"b">> => 2}},
    {ok, Token} = encode(?TEST_KEY, Data, 1),
    {ok, Data} = decode(?TEST_KEY, Token),
    sleep(1),
    invalid_token = decode(?TEST_KEY, Token).

-endif.


split_token(Token) ->
    [_, _, _] = binary:split(Token, [<<".">>], [global]).

-ifdef(TEST).

split_token_test() ->
    ?assert(split_token(<<"ab.de.gh">>) =:= [<<"ab">>, <<"de">>, <<"gh">>]).

-endif.

sign(<<"HS256">>, Payload, Key) ->
    base64url:encode(crypto:mac(hmac, sha256, Key, Payload));
sign(_, _, _) ->
    throw(unsupported_algorithm).

validate_sign(Alg, Key, Header, Body, Sign) ->
    Payload = <<Header/binary, ".", Body/binary>>,
    Sign =:= sign(Alg, Payload, Key).

header(Alg) ->
    #{<<"alg">> => Alg, <<"typ">> => <<"JWT">>}.

epoch() ->
    erlang:system_time(seconds).

