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
-export([validate_certs/3]). % to be moved to somewhere in ssl sometime later
-export([create_ocsp_request/2]).
-export([verify_ocsp_response/2]).

%% type
-type cert()    :: binary() | #'OTPCertificate'{} | #'OTPTBSCertificate'{}.
-type cachain() :: [binary()] | [#'OTPCertificate'{}].

-define(DER_NULL, <<5, 0>>).
-define(EXT_NULL, null).

%%%===================================================================
%%% API
%%%===================================================================

%% to be moved to somewhere in ssl sometime later
validate_certs(Certs, CAChain, Url) when is_list(Certs) ->
    case ensure_inets() of
        ok ->
            Request = create_ocsp_request(Certs, CAChain),
            Response = httpc:request(
                post, {Url, [], "application/ocsp-request", Request},
                [], []),
            verify_ocsp_response(Response, CAChain);
        {error, Reason} ->
            {error, Reason}
    end.


-spec create_ocsp_request(cert(), cachain()) -> {ok, binary()} |
                                                {error, term()}.
create_ocsp_request(Certs, CAChain) when is_list(Certs) ->
    Requests =
        [create_request(create_certID(Cert, CAChain), ?EXT_NULL) ||
         Cert <- Certs],
    TBSRequest = #'TBSRequest'{requestList = Requests},
    {ok, Bytes} = 'OTP-PUB-KEY':encode(
        'OCSPRequest', #'OCSPRequest'{tbsRequest = TBSRequest}),
    Bytes.


% -spec verify_ocsp_response(Body :: binary()) -> ok.
verify_ocsp_response(HTTPResponse, CAChain) ->
    case get_http_body(HTTPResponse) of
        {ok, Body} ->
            handle_response(Body, CAChain);
        {error, Reason} ->
            {error, Reason}
    end.


%%%===================================================================
%%% Internal functions
%%%===================================================================

%% to be moved to somewhere in ssl sometime later
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

handle_response(HTTPBody, CAChain) ->
    {ok, OCSPResponse} = 'OTP-PUB-KEY':decode('OCSPResponse', HTTPBody),
    case OCSPResponse#'OCSPResponse'.responseStatus of
        successful ->
            handle_response_bytes(
                OCSPResponse#'OCSPResponse'.responseBytes, CAChain);
        Error ->
            {error, Error}
    end.

handle_response_bytes(#'ResponseBytes'{
                          responseType = ?'id-pkix-ocsp-basic',
                          response = Data}, CAChain) ->
    {ok, #'BasicOCSPResponse'{
        tbsResponseData = ResponseData,
        signatureAlgorithm = SignedAlgo,
        signature = Signature,
        certs = Certs
    }} = 'OTP-PUB-KEY':decode('BasicOCSPResponse', Data),

    #'ResponseData'{
        responses = Responses,
        responderID = ResponderID
    } = ResponseData,

    case verify_signature(
             'OTP-PUB-KEY':encode('ResponseData', ResponseData),
             SignedAlgo, Signature, Certs ++ CAChain, ResponderID) of
        ok ->
            [{R#'SingleResponse'.certID, R#'SingleResponse'.certStatus} ||
              R <- Responses];
        {error, Reason} ->
            {error, Reason}
    end;
handle_response_bytes(#'ResponseBytes'{responseType = RespType}, _CAChain) ->
    {error, response_type_not_supported, RespType}.


verify_signature(ResponseData, SignedAlgo, Signature, Certs, ResponderID)
  when is_list(Certs) ->
    case find_signer_cert(ResponderID, Certs) of
        {ok, Cert} ->
            do_verify_signature(ResponseData, Signature, SignedAlgo, Cert);
        {error, Reason} ->
            {error, Reason}
    end.

do_verify_signature(ResponseData, Signature, AlgorithmID, SignerCert) ->
    {DigestType, _SignatureType} = public_key:pkix_sign_types(AlgorithmID),
    case public_key:verify(
            ResponseData, DigestType, Signature,
            get_public_key_rec(SignerCert)) of
        true -> ok;
        false ->
            {error, bad_signature}
    end.

find_signer_cert(_ResponderID, []) ->
    {error, ocsp_signer_cert_not_found};
find_signer_cert(ResponderID, [Cert | TCerts]) ->
    case is_signer(ResponderID, otp_cert(Cert)) of
        true ->
            {ok, Cert};
        false ->
            find_signer_cert(ResponderID, TCerts)
    end.

%% cannot compare like this
is_signer({byName, Name}, Cert) ->
    erlang:display({bynnnnnnnnname, Name, get_subject_name(Cert)}),
    Name == get_subject_name(Cert);
%% Key -- SHA-1 hash of responder's public key
is_signer({byKey, Key}, Cert) ->
    erlang:display({bykkkkkkkkkkkkkey, Key, crypto:hash(sha, get_public_key(Cert))}),
    Key == crypto:hash(sha, get_public_key(Cert)).

get_subject_name(Cert) ->
    #'OTPCertificate'{tbsCertificate = TbsCert} = otp_cert(Cert),
    TbsCert#'OTPTBSCertificate'.subject.

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

-spec create_certID(cert(), cachain()) -> #'CertID'{}.
create_certID(Cert, CAChain) ->    
    #'CertID'{
        hashAlgorithm = get_hash_algorithm(),
        issuerNameHash = hash_issuer_name(get_issuer_name(Cert)),
        issuerKeyHash =
            hash_issuer_key(get_public_key(get_issuer_cert(Cert, CAChain))),
        serialNumber = get_serial_num(Cert)
    }.

-spec get_issuer_name(cert()) -> string().
get_issuer_name(Cert) ->
    #'OTPCertificate'{tbsCertificate = TbsCert} = otp_cert(Cert),
    public_key:pkix_encode('Name', TbsCert#'OTPTBSCertificate'.issuer, otp).

-spec get_public_key(cert()) -> string().
get_public_key(Cert) ->
    #'OTPCertificate'{tbsCertificate = TbsCert} = otp_cert(Cert),
    PKInfo = TbsCert#'OTPTBSCertificate'.subjectPublicKeyInfo,
    public_key:pkix_encode(
        pubkey_cert_records:supportedPublicKeyAlgorithms(
            PKInfo#'OTPSubjectPublicKeyInfo'.algorithm#'PublicKeyAlgorithm'.algorithm),
        PKInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey, otp
    ).

get_public_key_rec(Cert) ->
    #'OTPCertificate'{tbsCertificate = TbsCert} = otp_cert(Cert),
    PKInfo = TbsCert#'OTPTBSCertificate'.subjectPublicKeyInfo,
    PKInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey.

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
        algorithm = ?'id-sha256',
        parameters = ?DER_NULL
    }.

-spec hash_issuer_name(Issuer :: binary()) -> Digest :: binary().
hash_issuer_name(Issuer) ->
    crypto:hash(sha256, Issuer).

-spec hash_issuer_key(Key :: term()) -> Digest :: binary().
hash_issuer_key(Key) ->
    crypto:hash(sha256, Key).

-spec get_serial_num(cert()) -> SerialNumber :: string().
get_serial_num(Cert) ->
    #'OTPCertificate'{tbsCertificate = TbsCert} = otp_cert(Cert),
    TbsCert#'OTPTBSCertificate'.serialNumber.

-spec otp_cert(cert()) -> #'OTPCertificate'{}.
otp_cert(Cert) when is_binary(Cert) ->
    public_key:pkix_decode_cert(Cert, otp);
otp_cert(#'OTPCertificate'{} = Cert) ->
    Cert;
otp_cert(#'Certificate'{} = Cert) ->
    public_key:pkix_decode_cert(
        public_key:der_encode('Certificate', Cert), otp
    ).