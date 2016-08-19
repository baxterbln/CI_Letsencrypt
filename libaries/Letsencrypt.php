<?php if ( ! defined('BASEPATH')) exit('No direct script access allowed');

class Letsencrypt
{
    public $country_code = 'DE';
    public $state = "Germany";
    public $mailto = '';

    private $logger;
    private $client;
    private $license;
    private $accountDirectory;

    public function __construct($params = array())
    {
        $this->_CI = & get_instance();

        $this->_CI->config->load('letsencrypt');

        $this->license = $this->_CI->config->item('certificate_license');
        $this->client = new Client( $this->_CI->config->item('certificate_api') );
        $this->accountDirectory = $this->_CI->config->item('certificate_path') . '/_account';

        foreach ($params as $property => $value)
        {
            $this->$property = $value;
        }
    }

    public function init_account()
    {
        if (!file_exists($this->accountDirectory) && !@mkdir($this->accountDirectory, 0755, true)) {
            $this->log("Directory  $this->accountDirectory is not exist");
            throw new \RuntimeException("Couldn't create directory to expose private key: ${$this->accountDirectory}");
        }

        if (!is_file($this->accountDirectory . '/private.pem')) {
            // generate and save new private key for account
            // ---------------------------------------------
            $this->log('Starting new account registration');
            $this->generate_key(dirname($this->accountDirectory . '/private.pem'));
            $this->post_new_reg();
            $this->log('New account certificate registered');
        } else {
            $this->log('Account already registered. Continuing.');

        }
    }

    public function sign_domains(array $domains, $reuseCsr = false)
    {
        $this->log('Starting certificate generation process for domains');

        $privateAccountKey = $this->read_private_key($this->accountDirectory . '/private.pem');
        $account_key_details = openssl_pkey_get_details($privateAccountKey);

        // start domains authentication
        // ----------------------------
        foreach ($domains as $domain) {

            // 1. getting available authentication options
            // -------------------------------------------

            $this->log("Requesting challenge for $domain");

            $response = $this->signed_request(
                "/acme/new-authz",
                array("resource" => "new-authz", "identifier" => array("type" => "dns", "value" => $domain))
            );

            // choose http-01 challange only
            $challenge = array_reduce($response['challenges'], function ($v, $w) {
                return $v ? $v : ($w['type'] == 'http-01' ? $w : false);
            });
            if (!$challenge) throw new \RuntimeException("HTTP Challenge for $domain is not available. Whole response: " . json_encode($response));

            $this->log("Got challenge token for $domain");
            $location = $this->client->get_last_location();


            // 2. saving authentication token for web verification
            // ---------------------------------------------------

            $directory = $this->_CI->config->item('certificate_path') . '/.well-known/acme-challenge';
            $token_path = $directory . '/' . $challenge['token'];

            $this->log("Check $directory");
            if (!file_exists($directory) && !@mkdir($directory, 0755, true)) {
                $this->log("Directory  $directory is not exist");
                throw new \RuntimeException("Couldn't create directory to expose challenge: ${tokenPath}");
            }

            $header = array(
                // need to be in precise order!
                "e" => Base64_safe_encoder::encode($account_key_details["rsa"]["e"]),
                "kty" => "RSA",
                "n" => Base64_safe_encoder::encode($account_key_details["rsa"]["n"])

            );
            $payload = $challenge['token'] . '.' . Base64_safe_encoder::encode(hash('sha256', json_encode($header), true));

            file_put_contents($token_path, $payload);
            chmod($token_path, 0644);

            // 3. verification process itself
            // -------------------------------

            $uri = "http://${domain}/.well-known/acme-challenge/${challenge['token']}";

            $this->log("Token for $domain saved at $token_path and should be available at $uri");

            // simple self check
            if ($payload !== trim(@file_get_contents($uri))) {
                throw new \RuntimeException("Please check $uri - token not available");
            }

            $this->log("Sending request to challenge");

            // send request to challenge
            $result = $this->signed_request(
                $challenge['uri'],
                array(
                    "resource" => "challenge",
                    "type" => "http-01",
                    "keyAuthorization" => $payload,
                    "token" => $challenge['token']
                )
            );

            // waiting loop
            do {
                if (empty($result['status']) || $result['status'] == "invalid") {
                    throw new \RuntimeException("Verification ended with error: " . json_encode($result));
                }
                $ended = !($result['status'] === "pending");

                if (!$ended) {
                    $this->log("Verification pending, sleeping 1s");
                    sleep(1);
                }

                $result = $this->client->get($location);

            } while (!$ended);

            $this->log("Verification ended with status: ${result['status']}");
            @unlink($token_path);
        }

        // requesting certificate
        // ----------------------
        $domainPath = $this->get_domain_path(reset($domains));

        // generate private key for domain if not exist
        if (!is_dir($domainPath) || !is_file($domainPath . '/private.pem')) {
            $this->generate_key($domainPath);
        }

        // load domain key
        $privateDomainKey = $this->read_private_key($domainPath . '/private.pem');

        $this->client->get_last_links();

        $csr = $reuseCsr && is_file($domainPath . "/last.csr")?
            $this->get_csr_content($domainPath . "/last.csr") :
            $this->generate_csr($privateDomainKey, $domains);

        // request certificates creation
        $result = $this->signed_request(
            "/acme/new-cert",
            array('resource' => 'new-cert', 'csr' => $csr)
        );
        if ($this->client->get_last_code() !== 201) {
            throw new \RuntimeException("Invalid response code: " . $this->client->get_last_code() . ", " . json_encode($result));
        }
        $location = $this->client->get_last_location();

        // waiting loop
        $certificates = array();
        while (1) {
            $this->client->get_last_links();

            $result = $this->client->get($location);

            if ($this->client->get_last_code() == 202) {

                $this->log("Certificate generation pending, sleeping 1s");
                sleep(1);

            } else if ($this->client->get_last_code() == 200) {

                $this->log("Got certificate! YAY!");
                $certificates[] = $this->parse_pem_from_body($result);


                foreach ($this->client->get_last_links() as $link) {
                    $this->log("Requesting chained cert at $link");
                    $result = $this->client->get($link);
                    $certificates[] = $this->parse_pem_from_body($result);
                }

                break;
            } else {

                throw new \RuntimeException("Can't get certificate: HTTP code " . $this->client->get_last_code());

            }
        }

        if (empty($certificates)) throw new \RuntimeException('No certificates generated');

        $this->log("Saving fullchain.pem");
        file_put_contents($domainPath . '/fullchain.pem', implode("\n", $certificates));

        $this->log("Saving cert.pem");
        file_put_contents($domainPath . '/cert.pem', array_shift($certificates));

        $this->log("Saving chain.pem");
        file_put_contents($domainPath . "/chain.pem", implode("\n", $certificates));

        $this->log("Done !!§§!");

        return true;
    }

    // Not finished
    public function revoke_certificate($domain)
    {
        $this->log("Revoke certificate for $domain");

        $certificate = $this->_CI->config->item('certificate_path') . '/_domains/'.$domain.'/cert.pem';

        if (false === ($data = @file_get_contents($certificate))){
            $this->log('Failed to open cert: '.$certificate);
			throw new Exception('Failed to open cert: '.$certificate);
		}

        if (false === ($x509 = @openssl_x509_read($data))){
            $this->log('Failed to parse cert: '.$certificate."\n".openssl_error_string());
			throw new Exception('Failed to parse cert: '.$certificate."\n".openssl_error_string());
		}

		if (false === (@openssl_x509_export($x509, $cert))){
            $this->log('Failed to parse cert: '.$certificate."\n".openssl_error_string());
			throw new Exception('Failed to parse cert: '.$certificate."\n".openssl_error_string());
		}

        $begin = "CERTIFICATE-----";
        $end = "----END";
        $pem = substr($data, strpos($data, $begin) + strlen($begin));
        $pem = substr($pem, 0, strpos($pem, $end));

        $cert = Base64_safe_encoder::encode_revoke(base64_decode($pem));

        $response = $this->signed_request(
                        "/acme/revoke-cert",
                        array('resource' => 'revoke-cert', "certificate" => $cert)
                    );

        if (!$response) {
            $this->log("Certificate revoked!");
            return true;
        }
        else if (isset($response['status']) && $response['status'] == 409) {
            $this->log("Certificate already revoked!");
            return true;
        }
        else {
            if (isset($response['code'])) {
		        throw new Exception('unexpected http status code: '.$response['code']);
            }
            if (isset($response['status'])) {
		        throw new Exception('unexpected http status code: '.$response['status']);
            }
		}
    }

    // Not supported by acme at the moment
    public function recover_account($mailto)
    {
        $this->log("Recover Account");
        $params = array(
            'resource' => 'recover-reg',
            'method'   => 'contact',
            'base'     => '',
            'contact' => array(
                'mailto:'.$this->mailto,
            ),
        );

        $response = $this->signed_request("/acme/recover-reg", $params);
    }

    private function get_domain_path($domain)
    {
        return $this->_CI->config->item('certificate_path') . '/_domains/'.$domain . '/';
    }

    private function read_private_key($path)
    {
        if (($key = openssl_pkey_get_private('file://' . $path)) === FALSE) {
            throw new \RuntimeException(openssl_error_string());
        }

        return $key;
    }

    private function parse_pem_from_body($body)
    {
        $pem = chunk_split(base64_encode($body), 64, "\n");
        return "-----BEGIN CERTIFICATE-----\n" . $pem . "-----END CERTIFICATE-----\n";
    }

    private function post_new_reg()
    {
        $this->log('Sending registration to letsencrypt server');

        $result = $this->signed_request(
            '/acme/new-reg',
            array('resource' => 'new-reg', 'contact'=>array('mailto:'.$this->mailto), 'agreement' => $this->license)
        );

        if(!isset($result['createdAt'])) {
            throw new \RuntimeException('post_new_reg error');
        }

        return $result;
    }

    private function generate_csr($privateKey, array $domains)
    {
        $domain = reset($domains);
        $san = implode(",", array_map(function ($dns) {
            return "DNS:" . $dns;
        }, $domains));
        $tmpConf = tmpfile();
        $tmpConfMeta = stream_get_meta_data($tmpConf);
        $tmpConfPath = $tmpConfMeta["uri"];

        // workaround to get SAN working
        fwrite($tmpConf,
            'HOME = .
RANDFILE = $ENV::HOME/.rnd
[ req ]
default_bits = 2048
default_keyfile = privkey.pem
distinguished_name = req_distinguished_name
req_extensions = v3_req
[ req_distinguished_name ]
countryName = Country Name (2 letter code)
[ v3_req ]
basicConstraints = CA:FALSE
subjectAltName = ' . $san . '
keyUsage = nonRepudiation, digitalSignature, keyEncipherment');

        $csr = openssl_csr_new(
            array(
                "CN" => $domain,
                "ST" => $this->state,
                "C" => $this->countryCode,
                "O" => "Unknown",
            ),
            $privateKey,
            array(
                "config" => $tmpConfPath,
                "digest_alg" => "sha256"
            )
        );

        if (!$csr) throw new \RuntimeException("CSR couldn't be generated! " . openssl_error_string());

        openssl_csr_export($csr, $csr);
        fclose($tmpConf);

        $csrPath = $this->get_domain_path($domain) . "/last.csr";
        file_put_contents($csrPath, $csr);

        return $this->get_csr_content($csrPath);
    }

    private function get_csr_content($csrPath) {
        $csr = file_get_contents($csrPath);

        preg_match('~REQUEST-----(.*)-----END~s', $csr, $matches);

        return trim(Base64_safe_encoder::encode(base64_decode($matches[1])));
    }

    private function generate_key($outputDirectory)
    {
        $res = openssl_pkey_new(array(
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
            "private_key_bits" => 4096,
        ));

        if(!openssl_pkey_export($res, $privateKey)) {
            throw new \RuntimeException("Key export failed!");
        }

        $details = openssl_pkey_get_details($res);

        if(!is_dir($outputDirectory)) @mkdir($outputDirectory, 0700, true);
        if(!is_dir($outputDirectory)) throw new \RuntimeException("Cant't create directory $outputDirectory");

        file_put_contents($outputDirectory.'/private.pem', $privateKey);
        file_put_contents($outputDirectory.'/public.pem', $details['key']);
    }

    private function signed_request($uri, array $payload)
    {
        $privateKey = $this->read_private_key($this->accountDirectory . '/private.pem');
        $details = openssl_pkey_get_details($privateKey);

        $header = array(
            "alg" => "RS256",
            "jwk" => array(
                "kty" => "RSA",
                "n" => Base64_safe_encoder::encode($details["rsa"]["n"]),
                "e" => Base64_safe_encoder::encode($details["rsa"]["e"]),
            )
        );

        $protected = $header;
        $protected["nonce"] = $this->client->get_last_nonce();


        $payload64 = Base64_safe_encoder::encode(str_replace('\\/', '/', json_encode($payload)));
        $protected64 = Base64_safe_encoder::encode(json_encode($protected));

        openssl_sign($protected64.'.'.$payload64, $signed, $privateKey, "SHA256");

        $signed64 = Base64_safe_encoder::encode($signed);

        $data = array(
            'header' => $header,
            'protected' => $protected64,
            'payload' => $payload64,
            'signature' => $signed64
        );

        $this->log("Sending signed request to $uri");

        return $this->client->post($uri, json_encode($data));
    }

    protected function log($message)
    {
        if($this->logger) {
            log_message('debug', $message);
        }
    }
}

class Client
{
    private $lastCode;
    private $lastHeader;

    private $base;

    public function __construct($base)
    {
        $this->base = $base;
    }

    private function curl($method, $url, $data = null)
    {
        $url = preg_match('~^http~', $url) ? $url : $this->base.$url;

        $headers = array('Accept: application/json', 'Content-Type: application/json');
        $handle = curl_init();
        curl_setopt($handle, CURLOPT_URL, $url);
        curl_setopt($handle, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_HEADER, true);

        // DO NOT DO THAT!
        // curl_setopt($handle, CURLOPT_SSL_VERIFYHOST, false);
        // curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, false);

        switch ($method) {
            case 'GET':
                break;
            case 'POST':
                curl_setopt($handle, CURLOPT_POST, true);
                curl_setopt($handle, CURLOPT_POSTFIELDS, $data);
                break;
        }
        $response = curl_exec($handle);

        if(curl_errno($handle)) {
            throw new \RuntimeException('Curl: '.curl_error($handle));
        }

        $header_size = curl_getinfo($handle, CURLINFO_HEADER_SIZE);

        $header = substr($response, 0, $header_size);
        $body = substr($response, $header_size);

        $this->lastHeader = $header;
        $this->lastCode = curl_getinfo($handle, CURLINFO_HTTP_CODE);

        $data = json_decode($body, true);
        return $data === null ? $body : $data;
    }

    public function post($url, $data)
    {
        return $this->curl('POST', $url, $data);
    }

    public function get($url)
    {
        return $this->curl('GET', $url);
    }

    public function get_last_nonce()
    {
        if(preg_match('~Replay\-Nonce: (.+)~i', $this->lastHeader, $matches)) {
            return trim($matches[1]);
        }

        $this->curl('GET', '/directory');
        return $this->get_last_nonce();
    }

    public function get_last_location()
    {
        if(preg_match('~Location: (.+)~i', $this->lastHeader, $matches)) {
            return trim($matches[1]);
        }
        return null;
    }

    public function get_last_code()
    {
        return $this->lastCode;
    }

    public function get_last_links()
    {
        preg_match_all('~Link: <(.+)>;rel="up"~', $this->lastHeader, $matches);
        return $matches[1];
    }
}

class Base64_safe_encoder
{
    public static function encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    public static function decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    public static function encode_revoke($input)
    {
        return rtrim(strtr(base64_encode($input), '+/', '-_'), '=');
    }
}
