`simplejwt:encode` only support JSON-compatible data like number,
string, list, maps...

data like tuple is not JSON-compatible.

```erlang
{ok, T} = simplejwt:encode(<<"key">>, {1,2,3}, 1000).
%  ** exception error: no match of right hand side value {failed,badarg}
```

Things that JSON do not support like atom will be converted to bianry:

```erlang
{ok, T} = simplejwt:encode(<<"key">>, blah, 1000).
%> {ok,<<"ey...J9.ey...n0.E4...4W"...>>}

simplejwt:decode(<<"key">>, T).
%> {ok,<<"blah">>}
```

only HS256 is supported now.

