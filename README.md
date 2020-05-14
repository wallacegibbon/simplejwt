## why there is a `encode_jsonerl`

First, `simplejwt:encode` only support JSON-compatible data like number,
string, list... data like tuple, is not JSON-compatible.

```erlang
{ok, T} = simplejwt:encode(<<"key">>, {1,2,3}, 1000).
%  ** exception error: no match of right hand side value {failed,badarg}
```

And it will convert atom to bianry automatically.

```erlang
{ok, T} = simplejwt:encode(<<"key">>, blah, 1000).
%> {ok,<<"ey...J9.ey...n0.E4...4W"...>>}

simplejwt:decode(<<"key">>, T).
%> {ok,<<"blah">>}
```

with [jsonerl][jsonerlurl], you can encode any erlang object.

```erlang
{ok, T} = simplejwt:encode_jsonerl(<<"key">>, {1,2,3}, 1000).
%> {ok,<<"ey...J9.eyJl...MiwzXX1"...>>}

simplejwt:decode_jsonerl(<<"key">>, T).
%> {ok,{1,2,3}}
```

## limits

only HS256 is supported now.


[jsonerlurl]: https://github.com/wallacegibbon/jsonerl

