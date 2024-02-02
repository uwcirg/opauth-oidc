<?php
/**
 * OpenID Connect strategy for Opauth
 *
 * More information on Opauth: http://opauth.org
 *
 * @package      Opauth.OidcStrategy
 * @license      MIT License
 */

class OidcStrategy extends OpauthStrategy{

    /**
     * Compulsory config keys, listed as unassociative arrays
     */
    public $expects = array('client_id', 'client_secret');

    /**
     * Optional config keys, without predefining any default values.
     */
    public $optionals = array(
        'redirect_uri',
        'scope',
        'authorization_endpoint',
        'token_endpoint',
        'userinfo_endpoint',
    );
    /**
     * Optional config keys with respective default values, listed as associative arrays
     * eg. array('scope' => 'email');
     */
    public $defaults = array(
        'redirect_uri' => '{complete_url_to_strategy}oauth2callback',
        'scope' => 'profile email openid'
    );

    /**
     * Auth request
     */
    public function request(){
        $params = array(
            'client_id' => $this->strategy['client_id'],
            'redirect_uri' => $this->strategy['redirect_uri'],
            'response_type' => 'code',
            'scope' => $this->strategy['scope']
        );

        $this->clientGet($this->strategy['authorization_endpoint'], $params);
    }

    /**
     * Internal callback, after OAuth
     */
    public function oauth2callback(){
        if (array_key_exists('code', $_GET) && !empty($_GET['code'])){
            $code = $_GET['code'];
            $params = array(
                'code' => $code,
                'client_id' => $this->strategy['client_id'],
                'client_secret' => $this->strategy['client_secret'],
                'redirect_uri' => $this->strategy['redirect_uri'],
                'grant_type' => 'authorization_code'
            );
            $response = $this->serverPost(
                $this->strategy['token_endpoint'],
                $params,
                null,
                $response_headers
            );

            $results = json_decode($response);

            if (!empty($results) && !empty($results->access_token)){
                $userinfo = $this->userinfo($results->access_token);
                $this->auth = array(
                    'sub' => $userinfo['sub'],
                    'info' => array(),
                    'credentials' => array(
                        'token' => $results->access_token,
                        'expires' => date('c', time() + $results->expires_in)
                    ),
                    'raw' => $userinfo
                );

                if (!empty($results->refresh_token)){
                    $this->auth['credentials']['refresh_token'] = $results->refresh_token;
                }

                // map OIDC user attributes to cPRO-specific names
                $this->mapProfile($userinfo, 'name', 'name');
                $this->mapProfile($userinfo, 'username', 'preferred_username');
                $this->mapProfile($userinfo, 'given_name', 'given_name');
                $this->mapProfile($userinfo, 'family_name', 'family_name');
                $this->mapProfile($userinfo, 'email_verified', 'email_verified');
                $this->callback();
            }
            else{
                $error = array(
                    'code' => 'access_token_error',
                    'message' => 'Failed when attempting to obtain access token',
                    'raw' => array(
                        'response' => $response,
                        'headers' => $response_headers
                    )
                );

                $this->errorCallback($error);
            }
        }
        else{
            $error = array(
                'code' => 'oauth2callback_error',
                'raw' => $_GET
            );

            $this->errorCallback($error);
        }
    }

    /**
     * Queries auth API for user info
     *
     * @param string $access_token
     * @return array Parsed JSON results
     */
    private function userinfo($access_token){
        // TODO look from JWT, when available
        $userinfo = $this->serverGet(
            $this->strategy['userinfo_endpoint'],
            array(),
            array('http' => array('header' => "Authorization: Bearer ${access_token}")),
            $response_headers
        );
        if (!empty($userinfo)){
            return $this->recursiveGetObjectVars(json_decode($userinfo));
        }
        else{
            $error = array(
                'code' => 'userinfo_error',
                'message' => 'Failed when attempting to query for user information',
                'raw' => array(
                    'response' => $userinfo,
                    'headers' => $response_headers
                )
            );

            $this->errorCallback($error);
        }
    }
}
