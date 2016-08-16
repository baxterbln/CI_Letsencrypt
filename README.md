#CI_Letsencrypt
Let´s encrypt library for codeigniter

The Letsencrypt CI Libary is simplified concept of ACME client implementation especially for Let's Encrypt service. It's goal is to have one easy to use codeigniter libary without dependencies.

Edit your config/letsencrypt.php set the folderpath for certificates.

For example, you use the path /home/certs, your private key will stored in /home/certs/_account and the certificates for all domains in /home/certs/_domains/DOMAINNAME

Usage:

1.) Create certificate:

    /* Set country for certificate request */
    $params = array('countryCode' => 'DE', 'state' => 'Germany', 'mailto' => 'your@mail.addr', 'logger' => null);

	/* Load libary */
	$this->load->library('Letsencrypt', $params);

	/* Initialize the account, this will create your account certificates, if not exist */
	$this->letsencrypt->initAccount();

	/* sign domain */
    try {
        $this->letsencrypt->signDomains(array('domain.com'));
        // your code....
    } catch (Exception $e) {
        echo 'Exception: ',  $e->getMessage(), "\n";
    }

2.) Revoke certificate:

	/* Load libary */
	$this->_CI->load->library('Letsencrypt');

	/* revoke domain */
    try {
        $this->letsencrypt->revokeCertificate('domain.com');
        // your code....
    } catch (Exception $e) {
        echo 'Exception: ',  $e->getMessage(), "\n";
    }

Requirements:
PHP 5.3 and up
OpenSSL extension
Curl extension
Codeigniter
