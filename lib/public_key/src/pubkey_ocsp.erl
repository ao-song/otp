%%
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 2011-2020. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% %CopyrightEnd%
%%
%% Description: Implements Online Certificate Status Protocol, RFC-6960
%%

-module(pubkey_ocsp).

-include("public_key.hrl").

%% API
-export([validate_certs/3]).
-export([create_ocsp_request/2]).
-export([check_ocsp_response/1]).

%% type
-type cert()    :: binary() | #'OTPCertificate'{} | #'OTPTBSCertificate'{}.
-type cachain() :: [binary()] | [#'OTPCertificate'{}] | [#'OTPCertificate'{}].

-define(DER_NULL, <<5, 0>>).
-define(EXT_NULL, null).

%%%===================================================================
%%% API
%%%===================================================================

validate_certs(Certs, CAChain, Url) when is_list(Certs) ->
    case ensure_inets() of
        ok ->
            Request = create_ocsp_request(Certs, CAChain),
            Response = httpc:request(
                post, {Url, [], "application/ocsp-request", Request},
                [], []),
            check_ocsp_response(Response);
        {error, Reason} ->
            {error, Reason}
    end.


-spec create_ocsp_request(cert(), cachain()) -> {ok, binary()} |
                                                {error, term()}.
create_ocsp_request(Certs, CAChain) when is_list(Certs) ->
    Requests =
        [create_request(get_certID(Cert, CAChain), ?EXT_NULL) || Cert <- Certs],
    TBSRequest = #'TBSRequest'{requestList = Requests},
    'OTP-PUB-KEY':encode(
        'OCSPRequest', #'OCSPRequest'{tbsRequest = TBSRequest}).


% -spec check_ocsp_response(Body :: binary()) -> ok.
check_ocsp_response(HTTPResponse) ->
    case get_http_body(HTTPResponse) of
        {ok, Body} ->
            handle_response(Body);
        {error, Reason} ->
            {error, Reason}
    end.


%%%===================================================================
%%% Internal functions
%%%===================================================================
ensure_inets() ->
    case inets:start() of
        ok ->
            ok;
        {error, {already_started, inets}} ->
            ok;
        {error, Reason} ->
            {stop, Reason}
    end.

-spec get_http_body(HTTPResponse :: tuple()) -> {ok, HTTPBody :: term()} |
                                                {error, term()}.
get_http_body({ok, {_StatusLine, _Headers, Body}}) ->
    {ok, Body};
get_http_body({ok, {_StatusCode, Body}}) ->
    {ok, Body};
get_http_body({error, Reason}) ->
    {error, Reason}.

handle_response(HTTPBody) ->
    {ok, OCSPResponse} = 'OTP-PUB-KEY':decode('OCSPResponse', HTTPBody),
    case OCSPResponse#'OCSPResponse'.responseStatus of
        successful ->
            handle_response_bytes(
                OCSPResponse#'OCSPResponse'.responseBytes);
        Error ->
            {error, Error}
    end.

handle_response_bytes(#'ResponseBytes'{
                          responseType = ?'id-pkix-ocsp-basic',
                          response  = Data}) ->
    #'BasicOCSPResponse'{
        tbsResponseData = ResponseData
    } = 'OTP-PUB-KEY':decode('BasicOCSPResponse', Data),

    #'ResponseData'{
        responses = Responses
    } = ResponseData,

    verify_signature(),

    [{R#'SingleResponse'.certID, R#'SingleResponse'.certStatus}
     || R <- Responses];
handle_response_bytes(#'ResponseBytes'{responseType = RespType}) ->
    {error, response_type_not_supported, RespType}.


%% todo
verify_signature() -> ok.

-spec create_request(#'CertID'{}, [#'Extension'{}]) -> #'Request'{}.
create_request(CertID, ?EXT_NULL) ->
    #'Request'{
        reqCert = CertID
    };
create_request(CertID, Exts) ->
    #'Request'{
        reqCert = CertID,
        singleRequestExtensions = Exts
    }.

-spec get_certID(cert(), cachain()) -> #'CertID'{}.
get_certID(Cert, CAChain) ->
    #'CertID'{
        hashAlgorithm = get_hash_algorithm(),
        issuerNameHash = get_issuer_name_hash(get_issuer_name(Cert)),
        issuerKeyHash =
            get_issuer_key_hash(get_public_key(get_issuer_cert(Cert, CAChain))),
        serialNumber = get_serial_num(Cert)
    }.

-spec get_issuer_name(cert()) -> string().
get_issuer_name(Cert) ->
    #'OTPCertificate'{tbsCertificate = TbsCert} = otp_cert(Cert),
    TbsCert#'OTPTBSCertificate'.issuer.

-spec get_public_key(cert()) -> string().
get_public_key(Cert) ->
    #'OTPCertificate'{tbsCertificate = TbsCert} = otp_cert(Cert),
    PKInfo = TbsCert#'OTPTBSCertificate'.subjectPublicKeyInfo,
    PKInfo#'SubjectPublicKeyInfo'.subjectPublicKey.

-spec get_issuer_cert(cert(), cachain()) -> cert() | {error, issuer_not_found}.
%% self-signed?
get_issuer_cert(Cert, []) ->
    case public_key:pkix_is_self_signed(Cert) of
        true ->
            Cert;
        false ->
            {error, issuer_not_found}
    end;
get_issuer_cert(Cert, [IssuerCert | Chain]) ->
    case public_key:pkix_is_issuer(Cert, IssuerCert) of
        true ->
            IssuerCert;
        false ->
            get_issuer_cert(Cert, Chain)
    end.

-spec get_hash_algorithm() -> #'AlgorithmIdentifier'{}.
get_hash_algorithm() ->
    #'AlgorithmIdentifier'{
        algorithm = ?'id-sha512',
        parameters = ?DER_NULL
    }.

-spec get_issuer_name_hash(Issuer :: term()) -> Digest :: binary().
get_issuer_name_hash(Issuer) ->
    crypto:hash(sha512, public_key:pkix_encode('Name', Issuer, otp)).

-spec get_issuer_key_hash(Key :: term()) -> Digest :: binary().
get_issuer_key_hash(Key) ->
    crypto:hash(sha512, Key).

-spec get_serial_num(cert()) -> SerialNumber :: string().
get_serial_num(Cert) ->
    #'OTPCertificate'{tbsCertificate = TbsCert} = otp_cert(Cert),
    TbsCert#'OTPTBSCertificate'.serialNumber.

-spec otp_cert(cert()) -> #'OTPCertificate'{}.
otp_cert(Cert) when is_binary(Cert) ->
    public_key:pkix_decode_cert(Cert, otp);
otp_cert(#'OTPCertificate'{} = Cert) ->
    Cert.