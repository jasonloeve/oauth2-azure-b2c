<?php

namespace Onfire\OAuth2\Client\Provider;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Onfire\OAuth2\Client\Grant\JwtBearer;

class Azure extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * @var string
     */
    protected $tenant;

    /**
     * @var string
     */
    protected $editPolicy;

    /**
     * @var string
     */
    protected $resetPolicy;

    /**
     * @var string
     */
    protected $signinPolicy;


    /**
     * @var array|null
     */
    protected $scopes;

    /**
     * @var string
     */
    protected $redirectUri;

    /**
     * @var string
     */
    protected $clientId;

    /**
     * @var string
     */
    protected $clientSecret;

    /**
     * The contents of the private key used for app authentication
     * @var string
     */
    protected $clientCertificatePrivateKey = '';

    /**
     * @var array|null
     */
    protected $openIdConfiguration;

    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct($options, $collaborators);

        $this->grantFactory->setGrant('jwt_bearer', new JwtBearer());
    }

    /**
     * @param string $tenant
     * @param string $policy
     */
    protected function getOpenIdConfiguration($tenant, $policy) {

        if (!is_array($this->openIdConfiguration)) {
            $this->openIdConfiguration = [];
        }

        if (!array_key_exists($tenant, $this->openIdConfiguration)) {
            $openIdConfigurationUri = 'https://' . $tenant . '.b2clogin.com/' . $tenant . '.onmicrosoft.com/' . $policy . '/v2.0/.well-known/openid-configuration';

            $factory = $this->getRequestFactory();
            $request = $factory->getRequestWithOptions(
                'get',
                $openIdConfigurationUri,
                []
            );

            $response = $this->getParsedResponse($request);
            $this->openIdConfiguration[$tenant] = $response;
        }

        return $this->openIdConfiguration[$tenant];
    }

    /**
     * @inheritdoc
     */
    public function getBaseAuthorizationUrl()
    {
        $openIdConfiguration = $this->getOpenIdConfiguration($this->tenant, $this->signinPolicy);

//        echo '<pre>';
//        var_dump($openIdConfiguration);
//        echo '</pre>';
//        die();

        return $openIdConfiguration['authorization_endpoint'];
    }

    /**
     * @inheritdoc
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        $openIdConfiguration = $this->getOpenIdConfiguration($this->tenant, $this->signinPolicy);
        return $openIdConfiguration['token_endpoint'];
    }


    public function getResetUrl(array $params)
    {
        $openIdConfiguration = $this->getOpenIdConfiguration($this->tenant, $this->signinPolicy);
        return $openIdConfiguration['token_endpoint'];
    }

    /**
     * @inheritdoc
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return ''; // shouldn't that return such a URL?
    }

    /**
     * @inheritdoc
     */
    protected function getDefaultScopes()
    {
        return $this->scopes;
    }

    /**
     * @inheritdoc
     */
    protected function getAccessTokenRequest(array $params)
    {
        if ($this->clientCertificatePrivateKey && $this->clientCertificateThumbprint) {
            $header = [
                'x5t' => base64_encode(hex2bin($this->clientCertificateThumbprint)),
            ];
            $now = time();
            $payload = [
                'aud' => "https://login.microsoftonline.com/{$this->tenant}/oauth2/v2.0/token",
                'exp' => $now + 360,
                'iat' => $now,
                'iss' => $this->clientId,
                'jti' => bin2hex(random_bytes(20)),
                'nbf' => $now,
                'sub' => $this->clientId,
            ];
            $jwt = JWT::encode($payload, str_replace('\n', "\n", $this->clientCertificatePrivateKey), 'RS256', null, $header);

            unset($params['client_secret']);
            $params['client_assertion_type'] = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
            $params['client_assertion'] = $jwt;
        }

        return parent::getAccessTokenRequest($params);
    }

    /**
     * @inheritdoc
     */
    public function getAccessToken($grant, array $options = [])
    {
        return parent::getAccessToken($grant, $options);
    }

    /**
     * @inheritdoc
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
//        if (isset($data['odata.error']) || isset($data['error'])) {
//            if (isset($data['odata.error']['message']['value'])) {
//                $message = $data['odata.error']['message']['value'];
//            } elseif (isset($data['error']['message'])) {
//                $message = $data['error']['message'];
//            } elseif (isset($data['error']) && !is_array($data['error'])) {
//                $message = $data['error'];
//            } else {
//                $message = $response->getReasonPhrase();
//            }
//
//            if (isset($data['error_description']) && !is_array($data['error_description'])) {
//                $message .= PHP_EOL . $data['error_description'];
//            }
//
//            throw new IdentityProviderException(
//                $message,
//                $response->getStatusCode(),
//                $response->getBody()
//            );
//        }
    }

    /**
     * @inheritdoc
     */
    protected function createAccessToken(array $response, AbstractGrant $grant)
    {
        return new AccessToken($response, $this);
    }

    /**
     * @inheritdoc
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new AzureResourceOwner($response);
    }

    /**
     * @inheritdoc
     */
    public function getResourceOwner(AccessToken $token)
    {
        $data = $token->getIdTokenClaims();
        return $this->createResourceOwner($data, $token);
    }


//    public function getObjects($tenant, $ref, &$accessToken, $headers = [])
//    {
//        $objects = [];
//
//        $response = null;
//        do {
//            if (false === filter_var($ref, FILTER_VALIDATE_URL)) {
//                $ref = $tenant . '/' . $ref;
//            }
//
//            $response = $this->request('get', $ref, $accessToken, ['headers' => $headers]);
//            $values   = $response;
//            if (isset($response['value'])) {
//                $values = $response['value'];
//            }
//            foreach ($values as $value) {
//                $objects[] = $value;
//            }
//            if (isset($response['odata.nextLink'])) {
//                $ref = $response['odata.nextLink'];
//            } elseif (isset($response['@odata.nextLink'])) {
//                $ref = $response['@odata.nextLink'];
//            } else {
//                $ref = null;
//            }
//        } while (null != $ref);
//
//        return $objects;
//    }

    /**
     * @param $accessToken AccessToken|null
     * @return string
     */
//    public function getRootMicrosoftGraphUri($accessToken)
//    {
//        if (is_null($accessToken)) {
//            $tenant = $this->tenant;
//            $version = $this->endPointVersion;
//        } else {
//            $idTokenClaims = $accessToken->getIdTokenClaims();
//            $tenant = is_array($idTokenClaims) && array_key_exists('tid', $idTokenClaims) ? $idTokenClaims['tid'] : $this->tenant;
//            $version = is_array($idTokenClaims) && array_key_exists('ver', $idTokenClaims) ? $idTokenClaims['ver'] : $this->endPointVersion;
//        }
//        $openIdConfiguration = $this->getOpenIdConfiguration($tenant, $version);
//        return 'https://' . $openIdConfiguration['msgraph_host'];
//    }

    //public function get($ref, &$accessToken, $headers = [], $doNotWrap = false)
    //{
    //    $response = $this->request('get', $ref, $accessToken, ['headers' => $headers]);
    //    return $doNotWrap ? $response : $this->wrapResponse($response);
    //}
    //
    //public function post($ref, $body, &$accessToken, $headers = [])
    //{
    //    $response = $this->request('post', $ref, $accessToken, ['body' => $body, 'headers' => $headers]);
    //    return $this->wrapResponse($response);
    //}
    //
    //public function put($ref, $body, &$accessToken, $headers = [])
    //{
    //    $response = $this->request('put', $ref, $accessToken, ['body' => $body, 'headers' => $headers]);
    //    return $this->wrapResponse($response);
    //}
    //
    //public function delete($ref, &$accessToken, $headers = [])
    //{
    //    $response = $this->request('delete', $ref, $accessToken, ['headers' => $headers]);
    //    return $this->wrapResponse($response);
    //}
    //
    //public function patch($ref, $body, &$accessToken, $headers = [])
    //{
    //    $response = $this->request('patch', $ref, $accessToken, ['body' => $body, 'headers' => $headers]);
    //    return $this->wrapResponse($response);
    //}
    //
    //public function request($method, $ref, &$accessToken, $options = [])
    //{
    //    if ($accessToken->hasExpired()) {
    //        $accessToken = $this->getAccessToken('refresh_token', [
    //            'refresh_token' => $accessToken->getRefreshToken(),
    //        ]);
    //    }
    //
    //    $url = null;
    //    if (false !== filter_var($ref, FILTER_VALIDATE_URL)) {
    //        $url = $ref;
    //    } else {
    //        if (false !== strpos($this->urlAPI, 'graph.windows.net')) {
    //            $tenant = 'common';
    //            if (property_exists($this, 'tenant')) {
    //                $tenant = $this->tenant;
    //            }
    //            $ref = "$tenant/$ref";
    //
    //            $url = $this->urlAPI . $ref;
    //
    //            $url .= (false === strrpos($url, '?')) ? '?' : '&';
    //            $url .= 'api-version=' . $this->API_VERSION;
    //        } else {
    //            $url = $this->urlAPI . $ref;
    //        }
    //    }
    //
    //    if (isset($options['body']) && ('array' == gettype($options['body']) || 'object' == gettype($options['body']))) {
    //        $options['body'] = json_encode($options['body']);
    //    }
    //    if (!isset($options['headers']['Content-Type']) && isset($options['body'])) {
    //        $options['headers']['Content-Type'] = 'application/json';
    //    }
    //
    //    $request  = $this->getAuthenticatedRequest($method, $url, $accessToken, $options);
    //    $response = $this->getParsedResponse($request);
    //
    //    return $response;
    //}

    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * Obtain URL for logging out the user.
     *
     * @param $post_logout_redirect_uri string The URL which the user should be redirected to after logout
     *
     * @return string
     */
//    public function getLogoutUrl($post_logout_redirect_uri = "")
//    {
//        $openIdConfiguration = $this->getOpenIdConfiguration($this->tenant, $this->endPointVersion);
//        $logoutUri = $openIdConfiguration['end_session_endpoint'];
//
//        if (!empty($post_logout_redirect_uri)) {
//            $logoutUri .= '?post_logout_redirect_uri=' . rawurlencode($post_logout_redirect_uri);
//        }
//
//        return $logoutUri;
//    }

    /**
     * Validate the access token you received in your application.
     *
     * @param $accessToken string The access token you received in the authorization header.
     *
     * @return array
     */
    public function validateAccessToken($accessToken)
    {
        $keys        = $this->getJwtVerificationKeys();
        $tokenClaims = (array)JWT::decode($accessToken, $keys, ['RS256']);

        $this->validateTokenClaims($tokenClaims);

        return $tokenClaims;
    }

    /**
     * Validate the access token claims from an access token you received in your application.
     *
     * @param $tokenClaims array The token claims from an access token you received in the authorization header.
     *
     * @return void
     */
    public function validateTokenClaims($tokenClaims) {
        if ($this->getClientId() != $tokenClaims['aud']) {
            throw new \RuntimeException('The client_id / audience is invalid!');
        }
        if ($tokenClaims['nbf'] > time() || $tokenClaims['exp'] < time()) {
            // Additional validation is being performed in firebase/JWT itself
            throw new \RuntimeException('The id_token is invalid!');
        }

        if ('common' == $this->tenant) {
            $this->tenant = $tokenClaims['tid'];
        }

        $version = array_key_exists('ver', $tokenClaims) ? $tokenClaims['ver'] : $this->endPointVersion;
        $tenant = $this->getTenantDetails($this->tenant, $version);
        if ($tokenClaims['iss'] != $tenant['issuer']) {
            throw new \RuntimeException('Invalid token issuer (tokenClaims[iss]' . $tokenClaims['iss'] . ', tenant[issuer] ' . $tenant['issuer'] . ')!');
        }
    }

    /**
     * Get JWT verification keys from Azure Active Directory.
     *
     * @return array
     */
    public function getJwtVerificationKeys()
    {
        $openIdConfiguration = $this->getOpenIdConfiguration($this->tenant, $this->signinPolicy);
        $keysUri = $openIdConfiguration['jwks_uri'];

        $factory = $this->getRequestFactory();
        $request = $factory->getRequestWithOptions('get', $keysUri, []);

        $response = $this->getParsedResponse($request);

        $keys = [];
        foreach ($response['keys'] as $i => $keyinfo) {
            if (isset($keyinfo['x5c']) && is_array($keyinfo['x5c'])) {
                foreach ($keyinfo['x5c'] as $encodedkey) {
                    $cert =
                        '-----BEGIN CERTIFICATE-----' . PHP_EOL
                        . chunk_split($encodedkey, 64,  PHP_EOL)
                        . '-----END CERTIFICATE-----' . PHP_EOL;

                    $cert_object = openssl_x509_read($cert);

                    if ($cert_object === false) {
                        throw new \RuntimeException('An attempt to read ' . $encodedkey . ' as a certificate failed.');
                    }

                    $pkey_object = openssl_pkey_get_public($cert_object);

                    if ($pkey_object === false) {
                        throw new \RuntimeException('An attempt to read a public key from a ' . $encodedkey . ' certificate failed.');
                    }

                    $pkey_array = openssl_pkey_get_details($pkey_object);

                    if ($pkey_array === false) {
                        throw new \RuntimeException('An attempt to get a public key as an array from a ' . $encodedkey . ' certificate failed.');
                    }

                    $publicKey = $pkey_array ['key'];

                    $keys[$keyinfo['kid']] = new Key($publicKey, 'RS256');
                }
            } else if (isset($keyinfo['n']) && isset($keyinfo['e'])) {
                $pkey_object = JWK::parseKey($keyinfo);

                if ($pkey_object === false) {
                    throw new \RuntimeException('An attempt to read a public key from a ' . $keyinfo['n'] . ' certificate failed.');
                }

                $pkey_array = openssl_pkey_get_details($pkey_object);

                if ($pkey_array === false) {
                    throw new \RuntimeException('An attempt to get a public key as an array from a ' . $keyinfo['n'] . ' certificate failed.');
                }

                $publicKey = $pkey_array ['key'];

                $keys[$keyinfo['kid']] = new Key($publicKey, 'RS256');;
            }
        }

        return $keys;
    }

    /**
     * Get the specified tenant's details.
     *
     * @param string $tenant
     * @param string $policy
     *
     * @return array
     * @throws IdentityProviderException
     */
    public function getTenantDetails($tenant, $policy)
    {
        return $this->getOpenIdConfiguration($this->tenant, $this->signinPolicy);
    }

//    private function wrapResponse($response)
//    {
//        if (empty($response)) {
//            return;
//        } elseif (isset($response['value'])) {
//            return $response['value'];
//        }
//
//        return $response;
//    }
}
