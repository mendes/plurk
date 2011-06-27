<?php
class PlurkOAuthException extends Exception
{
}

class PlurkOAuth
{
    const REQUEST_TOKEN_URL = 'http://www.plurk.com/OAuth/request_token';
    const ACCESS_TOKEN_URL = 'http://www.plurk.com/OAuth/access_token';
    const AUTHORIZATION_URL = 'http://www.plurk.com/OAuth/authorize';

    protected $_baseurl = 'http://www.plurk.com/APP/';
    protected $_consumer_key;
    protected $_consumer_secret;

    protected $_request_auth_url = null;
    protected $_request_expire = null;
    protected $_request_callback_url = null;

    protected $_token = null;
    protected $_secret = null;


    /**
     * __construct
     *
     * @param string $consumer_key
     * @param string $consumer_secret
     * @access public
     * @return void
     */
    public function __construct($consumer_key, $consumer_secret)
    {
        $this->_consumer_key = $consumer_key;
        $this->_consumer_secret = $consumer_secret;
    }

    /**
     * setToken .. token . secret .... access token ................
     *
     * @param string $token
     * @param string $secret
     * @access public
     * @return void
     */
    public function setToken($token, $secret)
    {
        $this->_token = $token;
        $this->_secret = $secret;
    }

    /**
     * setRequestCallback ... Authorization ........
     *
     * @param string $callback_url
     * @access public
     * @return void
     */
    public function setRequestCallback($callback_url)
    {
        $this->_request_callback_url = $callback_url;
    }

    /**
     * _get_request_token .. Request Token .......................
     *
     * @access protected
     * @return void
     */
    protected function _get_request_token()
    {
        if (!is_null($this->_request_expire) and time() < $this->_request_expire) {
            return;
        }

        if (is_null($this->_request_callback_url)) {
            $message = $this->http(self::REQUEST_TOKEN_URL);
        } else {
            $message = $this->http(self::REQUEST_TOKEN_URL, array('oauth_params' => array('oauth_callback' => $this->_request_callback_url)));
        }
        $args = array();
        parse_str($message, $args);

        $this->_token = $args['oauth_token'];
        $this->_secret = $args['oauth_token_secret'];
        $this->_request_expire = time() + $args['oauth_expires_in'];
        $this->_request_auth_url = self::AUTHORIZATION_URL . '?oauth_token=' . $args['oauth_token'];
    }

    /**
     * getAuthURL .. Authorization ...
     * . function .... setToken($request_token, $request_token_secret) ...
     *
     * @param string/null $callback_url .... Authorization ......
     * @access public
     * @return string Authorization ..
     */
    public function getAuthURL($callback_url = null)
    {
        if ($callback_url != $this->_request_callback_url) {
            $this->_request_expire = null;
            $this->_request_callback_url = $callback_url;
        }
        return $this->_request_auth_url;
    }

    /**
     * getAccessToken .. Access Token ..... function ...... setToken($request_token, $request_token_secret)
     *
     * @param string $verifier_token . Authorization ........... verifier_token
     * @access public
     * @return array(
     *            $access_token
     *            $access_token_secret
     *         )
     */
    public function getAccessToken($verifier_token)
    {
        $message = $this->http(self::ACCESS_TOKEN_URL, array('oauth_params' => array('oauth_verifier' => $verifier_token)));
        $args = array();
        parse_str($message, $args);

        $this->_token = $args['oauth_token'];
        $this->_secret = $args['oauth_token_secret'];

        return array($this->_token, $this->_secret);
    }

    /**
     * getRequestTokenPair .. Request Token
     * . function .... setToken($request_token, $request_token_secret) ...
     *
     * @access public
     * @return void
     */
    public function getRequestTokenPair()
    {
        $this->_get_request_token();
        return array($this->_token, $this->_secret);
    }

    /**
     * http . $url . oauth api ..
     *
     * @param mixed $url
     * @param array $options
     *          method: get/post/delete .... METHOD
     *          get_params: array()  GET ..
     *          post_params: array() POST ..
     *          files:array() .......
     *          oauth_params: array() ... OAUTH ..
     * @access public
     * @return string url ....
     * @throw PixAPIException
     */
    public function http($url, $options = array())
    {
        // Oauth ....
        $oauth_args = array();
        $oauth_args['oauth_version'] = '1.0';
        $oauth_args['oauth_nonce'] = md5(uniqid());
        $oauth_args['oauth_timestamp'] = time();
        $oauth_args['oauth_consumer_key'] = $this->_consumer_key;
        if (!is_null($this->_token)) {
            $oauth_args['oauth_token'] = $this->_token;
        }
        $oauth_args['oauth_signature_method'] = 'HMAC-SHA1';

        if (isset($options['oauth_params'])) {
            foreach ($options['oauth_params'] as $key => $value) {
                $oauth_args[$key] = $value;
            }
        }

        // METHOD ..
        $parts = array();
        if (isset($options['method'])) {
            $parts[] = strtoupper($options['method']);
        } elseif (isset($options['post_params']) or isset($options['files'])) {
            $parts[] = 'POST';
        } else {
            $parts[] = 'GET';
        }

        // ..... get_params, ........
        if (isset($options['get_params']) and $options['get_params']) {
            if (false !== strpos('?', $url)) {
                $url .= '&';
            } else {
                $url .= '?';
            }
            $url .= http_build_query($options['get_params']);
        }
        $parts[] = rawurlencode(preg_replace('/\?.*$/', '', $url));

        if (isset($options['post_params'])) {
            foreach ($options['post_params'] as $key => $value) {
                if (is_null($value)) unset($options['post_params'][$key]);
            }
        }

        if (isset($options['get_params'])) {
            foreach ($options['get_params'] as $key => $value) {
                if (is_null($value)) unset($options['get_params'][$key]);
            }
        }
        // ....
        $args = $oauth_args;
        if (is_array($options['post_params'])) {
            $args = array_merge($options['post_params'], $args);
        }
        $args = isset($options['get_params']) ? array_merge($options['get_params'], $args) : $args;
        ksort($args);
        $args_parts = array();
        foreach ($args as $key => $value) {
            $args_parts[] = rawurlencode($key) . '=' . rawurlencode($value);
        }
        $parts[] = rawurlencode(implode('&', $args_parts));

        $base_string = implode('&', $parts);

        // .. oauth_signature
        $key_parts = array(
            rawurlencode($this->_consumer_secret),
            is_null($this->_secret) ? '' : rawurlencode($this->_secret)
        );
        $key = implode('&', $key_parts);
        $oauth_args['oauth_signature'] = base64_encode(hash_hmac('sha1', $base_string, $key, true));

        $oauth_header = 'OAuth ';
        $first = true;
        foreach ($oauth_args as $k => $v) {
            if (substr($k, 0, 5) != "oauth") continue;
            $oauth_header .= ($first ? '' : ',') . rawurlencode($k) . '="' . rawurlencode($v) . '"';
            $first = false;
        }

        if (isset($options['method'])) {
            $method_map = array('get' => HttpRequest::METH_GET, 'head' => HttpRequest::METH_HEAD, 'post' => HttpRequest::METH_POST, 'put' => HttpRequest::METH_PUT, 'delete' => HttpRequest::METH_DELETE);

            $request = new HttpRequest($url, $method_map[strtolower($options['method'])]);
        } elseif (isset($options['post_params']) or isset($options['files'])) {
            $request = new HttpRequest($url, HttpRequest::METH_POST);
        } else {
            $request = new HttpRequest($url, HttpRequest::METH_GET);
        }

        $request->setOptions($this->_http_options);

        $request->setHeaders(array('Authorization' => $oauth_header));
        if (isset($options['post_params'])) {
            $request->setPostFields($options['post_params']);
        }
        if (isset($options['files'])) {
            foreach ($options['files'] as $name => $file) {
                $request->addPostFile($name, $file);
            }
        }
        $message = $request->send();
        if ($message->getResponseCode() !== 200) {
            throw new PlurkOAuthException($message->getBody(), $message->getResponseCode());
        }
        return $message->getBody();
    }

    protected $_http_options = array();

    /**
     * setHttpOptions .. HTTP options
     *
     * @link http://php.net/manual/en/http.request.options.php
     * @param array $array
     * @access public
     * @return void
     */
    public function setHttpOptions($array)
    {
        $this->_http_options = array_merge($array, $this->_http_options);
    }

    public function plurkAdd($content, $qualifier = 'says')
    {
            $option = array('method' => 'POST', 'get_params' => array('content' => strval($content), 'qualifier' => $qualifier));
            $res = $this->http('http://www.plurk.com/APP/Timeline/plurkAdd', $option);
            return $res;
    }

    public function getOwnProfile()
    {
            $option = array('method' => 'GET');
            $res = $this->http('http://www.plurk.com/APP/Profile/getOwnProfile', $option);
            return $res;
    }

    public function getPublicProfile($user = null)
    {
            $option = array('method' => 'GET', 'get_params' => array('user_id' => $user));
            $res = $this->http('http://www.plurk.com/APP/Profile/getPublicProfile', $option);
            return $res;
    }
}

?>
