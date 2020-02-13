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

-module(ocsp_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").

-define(DEFAULT_URL,  "http://127.0.0.1:8080").
-define(USER_CERT,    "users/rootCAsigned/cert.crt").
-define(ROOT_CA_CERT, "CA/cert/rootCA.crt").

%% OCSP server flags
-define(INDEX,   "CA/index.txt").
-define(RSIGNER, "CA/ocsp/ocspSigning.crt").
-define(RKEY,    "CA/ocsp/ocspSigning.key").
-define(TEXT,    "log.txt").

%% Note: This directive should only be used in test suites.
-compile(export_all).

%%--------------------------------------------------------------------
%% Common Test interface functions -----------------------------------
%%--------------------------------------------------------------------

suite() -> 
    [].

all() -> 
    [validate_cert].

groups() -> 
    [].

%%--------------------------------------------------------------------
init_per_suite(Config) ->
    inets:start(),
    Cmd = start_ocsp_server(
        get_file(?INDEX, Config),
        get_file(?RSIGNER, Config),
        get_file(?RKEY, Config),
        get_file(?ROOT_CA_CERT, Config),
        get_file(?TEXT, Config)),
    [{server_pid, port_open(Cmd)} | Config].

end_per_suite(Config) ->
    Pid = ?config(server_pid, Config),
    os:cmd(io_lib:format("kill -9 ~p", [Pid])),
    file:delete("ocsp_SUITE_data/log.txt"),
    inets:stop().

%%--------------------------------------------------------------------

init_per_group(_GroupName, Config) ->
    Config.

end_per_group(_GroupName, Config) ->
    Config.

%%--------------------------------------------------------------------
init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%--------------------------------------------------------------------
%% Test Cases --------------------------------------------------------
%%--------------------------------------------------------------------

validate_cert() ->
    [{doc, "Validate a cert which is signed by rootCA."}].
validate_cert(Config) when is_list(Config) ->
    %% Url = "http://127.0.0.1:8080"
    Url = ?DEFAULT_URL,
    {ok, Cert}   = file:read_file(get_file(?USER_CERT, Config)),
    {ok, CACert} = file:read_file(get_file(?ROOT_CA_CERT, Config)),
    [{_CertID, {good, _StatusInfo}}] =
        pubkey_ocsp:validate_certs(decode_pem(Cert), decode_pem(CACert), Url).


%%--------------------------------------------------------------------
%% Intrernal functions -----------------------------------------------
%%--------------------------------------------------------------------
port_open(Cmd) ->
    {os_pid, Pid} = erlang:port_info(
        erlang:open_port({spawn, Cmd}, []), os_pid),
    Pid.

get_file(FileName, Config) ->
    Datadir = ?config(data_dir, Config),
    filename:join(Datadir, FileName).

start_ocsp_server(Index, Rsigner, Rkey, CACert, Text) ->
    "openssl ocsp -index " ++ Index ++
    " -port 8080" ++
    " -rsigner " ++ Rsigner ++
    " -rkey " ++ Rkey ++
    " -CA " ++ CACert ++
    " -text -out " ++ Text.

decode_pem(Data) ->
    [public_key:pkix_decode_cert(Der, otp) ||
     {'Certificate', Der, _IsEncrypted} <- public_key:pem_decode(Data)].




%% server: openssl ocsp -index ocsp_SUITE_data/CA/index.txt -port 8080 -rsigner ocsp_SUITE_data/CA/ocsp/ocspSigning.crt -rkey ocsp_SUITE_data/CA/ocsp/ocspSigning.key -CA ocsp_SUITE_data/CA/cert/rootCA.crt -text -out log.txt &
%% client: openssl ocsp -CAfile ocsp_SUITE_data/CA/cert/rootCA.crt -issuer ocsp_SUITE_data/CA/cert/rootCA.crt -cert ocsp_SUITE_data/users/rootCAsigned/cert.crt -url http://127.0.0.1:8080 -resp_text -noverify