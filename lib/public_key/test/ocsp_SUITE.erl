

validate_cert(ResponderURL, Certs, CAChain) when is_list(Certs) ->
    case ensure_inets() of
        ok ->
            Request = create_ocsp_request(Certs, CAChain),
            Response = httpc:request(
                post, {ResponderURL, [], "application/ocsp-request", Request},
                [], []),
            check_response(Response);
        {error, Reason} ->
            {error, Reason}
    end.


check_response({ok, {_StatusLine, _Headers, Body}}) ->
    'OTP-PUB-KEY':decode('OCSPResponse', Body);
check_response({ok, {_StatusCode, Body}}) ->
    'OTP-PUB-KEY':decode('OCSPResponse', Body);
check_response({error, Reason}) ->
    {error, Reason}.


ensure_inets() ->
    case inets:start() of
        ok ->
            ok;
        {error, {already_started, inets}} ->
            ok;
        {error, Reason} ->
            {stop, Reason}
    end.