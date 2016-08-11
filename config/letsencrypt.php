<?php
defined('BASEPATH') OR exit('No direct script access allowed');

# Develop API
$config['certificate_api'] = 'https://acme-staging.api.letsencrypt.org';

# Live API
//$config['certificat_api'] = 'https://acme-v01.api.letsencrypt.org';

$config['certificate_path'] = '/usr/local/conf/letsencrypt/';
$config['certificate_license'] = 'https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf';
