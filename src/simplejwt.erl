%%% for now, only HS256(HMAC+SHA256) is supported.

-module(simplejwt).

-export([encode/3,encode/4,decode/2]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

decode(Key, Token) ->
    try
	{ok,parse_token(Key, Token)}
    catch
	throw:format_error ->
	    {invalid_token,format_error};
	throw:expired ->
	    {invalid_token,expired};
	error:I ->
	    {invalid_token,I}
    end.

parse_token(Key, Token) ->
    [Header,Body,Sign] = split_token(Token),
    #{<<"alg">>:=Alg} = jsone:decode(base64url:decode(Header)),
    true = validate_sign(Alg, Key, Header, Body, Sign),
    Data = jsone:decode(base64url:decode(Body)),
    fetch_payload(Data).

fetch_payload(#{<<"exp">>:=Exp,<<"payload">>:=Val}) ->
    case Exp > epoch() of
	true ->
	    Val;
	_ ->
	    throw(expired)
    end;
fetch_payload(_) ->
    throw(format_error).

encode(Key, Data, ExpirationSeconds) ->
    encode(<<"HS256">>, Key, Data, ExpirationSeconds).

encode(Alg, Key, Data, ExpirationSeconds) ->
    try
	{ok,make_token(Alg, Key, Data, ExpirationSeconds)}
    catch
	error:I ->
	    {failed,I}
    end.

make_token(Alg, Key, Data, ExpirationSeconds) ->
    ExpireTime = ExpirationSeconds + epoch(),
    Body = base64url:encode(jsone:encode(#{<<"exp">>=>ExpireTime,
					   <<"payload">>=>Data})),
    Header = base64url:encode(jsone:encode(header(Alg))),
    Payload = <<Header/binary,".",Body/binary>>,
    Sign = sign(Alg, Payload, Key),
    <<Payload/binary,".",Sign/binary>>.


-ifdef(TEST).

-define(TEST_KEY, "hello, this is a test").

encode_test() ->
    Data = #{<<"a">>=>#{<<"b">>=>2}},
    {ok,Token} = encode(?TEST_KEY, Data, 60),
    %?debugFmt("token ~p~n", [Token]),
    {ok,D1} = decode(?TEST_KEY, Token),
    %?debugFmt("decoded ~p~n", [D1]),
    ?assertEqual(D1, Data).

sleep(Seconds) ->
    receive after Seconds * 1000 -> ok end.

expire_test() ->
    Data = #{<<"a">>=>#{<<"b">>=>2}},
    {ok,Token} = encode(?TEST_KEY, Data, 1),
    {ok,Data} = decode(?TEST_KEY, Token),
    sleep(2),
    R = decode(?TEST_KEY, Token),
    %?debugFmt("decode expired, ~p~n", [R]),
    {invalid_token,expired} = R.

-endif.


split_token(Token) ->
    [_,_,_] = binary:split(Token, [<<".">>], [global]).

-ifdef(TEST).

split_token_test() ->
    ?assertEqual(split_token(<<"ab.de.gh">>), [<<"ab">>,<<"de">>,<<"gh">>]).

-endif.

sign(<<"HS256">>, Payload, Key) ->
    base64url:encode(hmac_crypt(sha256, Key, Payload));
sign(_, _, _) ->
    throw(unsupported_algorithm).


-if(?OTP_RELEASE >= 22).

hmac_crypt(Alg, Key, Data) ->
    crypto:mac(hmac, Alg, Key, Data).

-else.

hmac_crypt(Alg, Key, Data) ->
    crypto:hmac(Alg, Key, Data).

-endif.


validate_sign(Alg, Key, Header, Body, Sign) ->
    Payload = <<Header/binary,".",Body/binary>>,
    Sign =:= sign(Alg, Payload, Key).

header(Alg) ->
    #{<<"alg">>=>Alg,<<"typ">>=><<"JWT">>}.

epoch() ->
    erlang:system_time(seconds).

