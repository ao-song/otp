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

-define(DEFAULT_URL, "http://127.0.0.1:8080").
-define(USER_CERT, "ocsp_SUITE_data/users/rootCAsigned/cert.crt").
-define(ROOT_CA_CERT, "ocsp_SUITE_data/CA/cert/rootCA.crt").
-define(OCSP_SERVER_CMD,
        "openssl ocsp -index ocsp_SUITE_data/CA/index.txt -port 8080"
        " -rsigner ocsp_SUITE_data/CA/ocsp/ocspSigning.crt "
        "-rkey ocsp_SUITE_data/CA/ocsp/ocspSigning.key "
        "-CA ocsp_SUITE_data/CA/cert/rootCA.crt"
        " -text -out ocsp_SUITE_data/log.txt &").

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
    [{ocsp_port, port_open(?OCSP_SERVER_CMD)} | Config].

end_per_suite(Config) ->
    port_close(?config(ocsp_port, Config)),
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
    Cert = ?USER_CERT,
    CACert = ?ROOT_CA_CERT,
    [_CertID, good] =
    pubkey_ocsp:validate_certs([Cert], [CACert], Url).


%%--------------------------------------------------------------------
%% Intrernal functions -----------------------------------------------
%%--------------------------------------------------------------------
port_open(Cmd) ->
    open_port({spawn, Cmd}, [exit_status]).


%% server: openssl ocsp -index CA/index.txt -port 8080 -rsigner CA/ocsp/ocspSigning.crt -rkey CA/ocsp/ocspSigning.key -CA CA/cert/rootCA.crt -text -out log.txt &
%% client: openssl ocsp -CAfile CA/cert/rootCA.crt -issuer CA/cert/rootCA.crt -cert users/rootCAsigned/cert.crt -url http://127.0.0.1:8080 -resp_text -noverify