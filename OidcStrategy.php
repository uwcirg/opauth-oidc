<?php
/**
 * OpenID Connect strategy for Opauth
 *
 * More information on Opauth: http://opauth.org
 *
 * @package      Opauth.OidcStrategy
 * @license      MIT License
 */
App::uses('DatabaseSessionPlusUserId', 'Datasource/Session');
App::uses('User', 'Model');
class OidcStrategy extends OpauthStrategy{

    /**
     * Compulsory config keys, listed as unassociative arrays
     */
    public $expects = array(
        'client_id',
        'client_secret',
        'authorization_endpoint',
        'token_endpoint',
        'userinfo_endpoint',
    );

    /**
     * Optional config keys, without predefining any default values.
     */
    public $optionals = array(
        'redirect_uri',
        'scope',
    );
    /**
     * Optional config keys with respective default values, listed as associative arrays
     * eg. array('scope' => 'email');
     */
    public $defaults = array(
        'redirect_uri' => '{complete_url_to_strategy}oauth2callback',
        'scope' => 'profile email openid'
    );

    public $hasRefresh = true;

    /**
     * Start authorization code request
     */
    public function request(){
        $querystring_params = array(
            'client_id' => $this->strategy['client_id'],
            'redirect_uri' => $this->strategy['redirect_uri'],
            'response_type' => 'code',
            'scope' => $this->strategy['scope']
        );

        CakeLog::write(LOG_DEBUG, "authorization request started; redirecting to IdP");
        $this->clientGet($this->strategy['authorization_endpoint'], $querystring_params);
    }

    /**
     * Internal callback; handle response to authorization request and request new access token
     */
    public function oauth2callback(){
        // CakeLog::write(LOG_DEBUG, __CLASS__."->".__FUNCTION__."(), here's what's in _GET:" . print_r($_GET, true) . ", here's what in the request headers:" . print_r(apache_request_headers(), true));
        if (!array_key_exists('code', $_GET) or empty($_GET['code'])){
            $error = array(
                'code' => 'oauth2callback_error',
                'raw' => $_GET
            );
            $this->errorCallback($error);
            return;
        }
        CakeLog::write(LOG_DEBUG, "user IdP authentication complete; received authorization code");

        // obtain authorization code (via querystring param) passed from IDP
        $code = $_GET['code'];
        $querystring_params = array(
            'code' => $code,
            'client_id' => $this->strategy['client_id'],
            'client_secret' => $this->strategy['client_secret'],
            'redirect_uri' => $this->strategy['redirect_uri'],
            'grant_type' => 'authorization_code'
        );
        CakeLog::write(LOG_DEBUG, "requesting access token");
        $response_body = $this->serverPost(
            $this->strategy['token_endpoint'],
            $querystring_params,
            null,
            $response_headers
        );
        $response_json = json_decode($response_body);
        if (
            !preg_match('/^HTTP.+200 OK/mi', $response_headers) or
            empty($response_json) or
            empty($response_json->access_token)
        ){
            $error = array(
                'code' => 'access_token_error',
                'message' => 'Failed when attempting to obtain access token',
                'raw' => array(
                    'response' => $response_body,
                    'headers' => $response_headers
                )
            );

            $this->errorCallback($error);
            return;
        }
        CakeLog::write(LOG_DEBUG, "successfully obtained access token");

        $this->auth = array(
            'raw' => array(),
            'info' => array(),
            'credentials' => array(
                'token' => $response_json->access_token,
                'expires' => date('c', time() + $response_json->expires_in)
            ),
        );
        if (!empty($response_json->refresh_token)){
            $this->auth['credentials']['refresh_token'] = $response_json->refresh_token;
        }
        if (!empty($response_json->id_token)){
            $this->auth['info']['id_token'] = $response_json->id_token;
        }
        $userinfo = $this->userinfo($this->auth);
        $this->auth['raw'] = $userinfo;

        // map OIDC user attributes to cPRO-specific names
        $this->mapProfile($userinfo, 'sub', 'sub');
        $this->mapProfile($userinfo, 'name', 'name');
        $this->mapProfile($userinfo, 'username', 'username');
        $this->mapProfile($userinfo, 'given_name', 'first_name');
        $this->mapProfile($userinfo, 'family_name', 'last_name');
        $this->mapProfile($userinfo, 'email_verified', 'email_verified');
        $this->mapProfile($userinfo, 'email', 'email');
        // OpAuth (OpauthAppController.php) requires uid to be populated, to set $request->data['validated']
        $this->mapProfile($userinfo, 'sub', 'uid');
        $this->mapProfile($userinfo, 'sub', 'external_id');
        $this->mapProfile($userinfo['access_token_data'], 'realm_access.roles', 'roles');
        $this->callback();
    }

    /**
     * Keycloak calls this to inform of logout from elsewhere.
     * URL: /auth/oidc/logoutCallback
     */
    public function logoutCallback(){
        //CakeLog::write(LOG_DEBUG, __CLASS__."->".__FUNCTION__."(), here's what's in _POST:" . print_r($_POST, true) . ", here's what in the request headers:" . print_r(apache_request_headers(), true));

        // TODO verify that it's KC calling this... would be impractical to bluff the sub tho.

        $logout_token = $_POST['logout_token']; //jwt

        // look in 'sub', map to users.external_id

        $jwt_decoded = $this->decode_jwt($logout_token);
        //CakeLog::write(LOG_DEBUG, __CLASS__."->".__FUNCTION__."(), here's what in the decoded jwt:" . print_r($jwt_decoded, true));
        $sub = $jwt_decoded->sub;

        $userObj = new User();
        $user = $userObj->find('first', array('conditions' => array('User.external_id' => $sub),
            'recursive' => -1));
        //CakeLog::write(LOG_DEBUG, __CLASS__."->".__FUNCTION__."(), mapped sub $sub to user:" . print_r($user, true));
        $userId = $user['User']['id'];

        $sessionObj = new DatabaseSessionPlusUserId();
        $deleteResult = $sessionObj->deleteByUserId($userId);

        // CakeLog::write(LOG_DEBUG, __CLASS__ ."->". __FUNCTION__ . "(), done.");
        CakeLog::write(LOG_DEBUG, "logged out user $userId by OIDC back-channel logout");
    }

    /**
     * Collect user data from OIDC tokens, or IdP userinfo endpoint
     *
     * @param array $auth_data
     * @return array JSON results
     */
    private function userinfo($auth_data){
        $userinfo = array();

        // add data from access token - keycloak only adds realm_access.roles and resource_access.account.roles to access token
        // NB the IdP may change the format of the access token at any time
        // in OIDC, although the IdP-issued (keycloak) access token is issued to the client, only the resource server is intended to consume it
        $access_token_data = $this->recursiveGetObjectVars(
            $this->decode_jwt($auth_data['credentials']['token'])
        );
        $userinfo = array_merge($userinfo, array("access_token_data" => $access_token_data));
        CakeLog::write(LOG_DEBUG, 'loaded auth data from access token');

        if (isset($this->auth['info']['id_token'])){
            $id_token_data = $this->recursiveGetObjectVars(
                $this->decode_jwt($this->auth['info']['id_token'])
            );
            $userinfo = array_merge($userinfo, $id_token_data);
            CakeLog::write(LOG_DEBUG, 'loaded userinfo from id token');
            return $userinfo;
        }

        $userinfo_response = $this->serverGet(
            $this->strategy['userinfo_endpoint'],
            array(),
            array('http' => array('header' => "Authorization: Bearer {$auth_data['credentials']['token']}")),
            $response_headers
        );
        if (
            !preg_match('/^HTTP.+200 OK/mi', $response_headers) or
            empty($userinfo_response)
        ){
            $error = array(
                'code' => 'userinfo_error',
                'message' => 'Failed when attempting to query for user information',
                'raw' => array(
                    'response' => $userinfo_response,
                    'headers' => $response_headers
                )
            );

            $this->errorCallback($error);
            return;
        }
        CakeLog::write(LOG_DEBUG, "retrieved userinfo from IdP");
        return $this->recursiveGetObjectVars(json_decode($userinfo_response));
    }

    /**
     * Decode and return JWT payload
     * TODO validate JWT signature
     * @param string $jwt
     * @return JWT payload
     */
    private function decode_jwt($jwt){
        list($encoded_header, $encoded_payload, $encoded_signature) = explode(".", $jwt);
        $payload = json_decode(base64_decode($encoded_payload));
        return $payload;
    }
}
