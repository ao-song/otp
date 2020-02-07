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

-behaviour(gen_server).

%% API
-export([start_link/0]).
-export([validate_cert/3]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%% type


-define(SERVER, ?MODULE).
-define(DER_NULL, <<5, 0>>).
-define(EXT_NULL, null).

-record(state, {
    is_inets_already_started = false,
    requestIDs = []
}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%--------------------------------------------------------------------
%% @doc
%% Check the status of a cert.
%%
%% @spec validate_cert(Cert, ResponderURL) -> ok
%% @end
%%--------------------------------------------------------------------
validate_cert(ResponderURL, Certs, CAChain) when is_list(Certs) ->
    gen_server:cast({validate_cert, ResponderURL, Certs, CAChain}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([]) ->
    case inets:start() of
        ok ->
            {ok, #state{}};
        {error, {already_started, inets}} ->
            {ok, #state{is_inets_already_started = true}};
        {error, Reason} ->
            {stop, Reason}
    end.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast({validate_cert, ResponderURL, Certs, CAChain},
            #state{requestIDs = ReqIDs} = State) ->
    Request = assemble_ocsp_request(Certs, CAChain),
    {ok, RequestId} = httpc:request(
        post, {ResponderURL, [], "application/ocsp-request", Request},
        [], [{sync, false}, {receiver, self()}]),
    {noreply, State#state{requestIDs = [RequestId | ReqIDs]}};
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info({http, {_RequestId, saved_to_file}}, State) ->
    {noreply, State};
handle_info({http, {_RequestId, {error, Reason}}}, State) ->
    %% debug
    io:format("httpc response error: ~p~n", [Reason]),
    {noreply, State};
handle_info({http, {_RequestId, {_StatusLine, _Headers, Body}}}, State) ->
    OCSPResponse = 'OTP-PUB-KEY':decode('OCSPResponse', Body),
    %% debug
    io:format("ocsp response: ~p~n", [OCSPResponse]),
    {noreply, State};
handle_info({http, {_RequestId, {_StatusCode, Body}}}, State) ->
    OCSPResponse = 'OTP-PUB-KEY':decode('OCSPResponse', Body),
    %% debug
    io:format("ocsp response: ~p~n", [OCSPResponse]),
    {noreply, State};
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, State) ->
    stop_inets(State),
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
        {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
stop_inets(#state{is_inets_already_started = false}) ->
    inets:stop();
stop_inets(_State) ->
    ok.

assemble_ocsp_request(Certs, CAChain) when is_list(Certs) ->
    Requests =
        [get_request(get_certID(Cert, CAChain), ?EXT_NULL) || Cert <- Certs],
    TBSRequest = #'TBSRequest'{requestList = Requests},
    'OTP-PUB-KEY':encode(
        'OCSPRequest', #'OCSPRequest'{tbsRequest = TBSRequest}).


get_request(CertID, ?EXT_NULL) ->
    #'Request'{
        reqCert = CertID
    };
get_request(CertID, Exts) ->
    #'Request'{
        reqCert = CertID,
        singleRequestExtensions = Exts
    }.

get_certID(Cert, CAChain) ->
    #'CertID'{
        hashAlgorithm = get_hash_algorithm(),
        issuerNameHash = get_issuer_name_hash(get_issuer_name(Cert)),
        issuerKeyHash =
            get_issuer_key_hash(get_public_key(get_issuer_cert(Cert, CAChain))),
        serialNumber = get_serial_num(Cert)
    }.

get_issuer_name(Cert) ->
    #'OTPCertificate'{tbsCertificate = TbsCert} = otp_cert(Cert),
    TbsCert#'OTPTBSCertificate'.issuer.

get_public_key(Cert) ->
    #'OTPCertificate'{tbsCertificate = TbsCert} = otp_cert(Cert),
    PKInfo = TbsCert#'OTPTBSCertificate'.subjectPublicKeyInfo,
    PKInfo#'SubjectPublicKeyInfo'.subjectPublicKey.

%% self-signed?
get_issuer_cert(Cert, []) ->
    case public_key:pkix_is_self_signed(Cert) of
        true ->
            Cert;
        false ->
            undefined
    end;
get_issuer_cert(Cert, [IssuerCert | Chain]) ->
    case public_key:pkix_is_issuer(Cert, IssuerCert) of
        true ->
            IssuerCert;
        false ->
            get_issuer_cert(Cert, Chain)
    end.

get_hash_algorithm() ->
    #'AlgorithmIdentifier'{
        algorithm = ?'id-sha512',
        parameters = ?DER_NULL
    }.

get_issuer_name_hash(Issuer) ->
    crypto:hash(sha512, public_key:pkix_encode('Name', Issuer, otp)).

get_issuer_key_hash(Key) ->
    crypto:hash(sha512, Key).

get_serial_num(Cert) ->
    #'OTPCertificate'{tbsCertificate = TbsCert} = otp_cert(Cert),
    TbsCert#'OTPTBSCertificate'.serialNumber.

otp_cert(Cert) when is_binary(Cert) ->
    public_key:pkix_decode_cert(Cert, plain);
otp_cert(#'OTPCertificate'{} = Cert) ->
    Cert.