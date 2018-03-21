<?php
/**
 * SoapClient extensions which adds ability to sign messages and open HTTPS connections
 * $Id$
 */

/**
 *
 * SOAP Client class with message signing and HTTPS connections
 *
 * SSL settings should be passed on instance creation within `options` associated array.
 * Available settings are identical to the HTTPRequest class settings, e.g.
 *
 *    $client = new SignedSoapClient('https://example.com?wsdl', array('ssl' => array('cert' => '/file',
 *          'certpasswd' => 'password')));
 *
 * SSL certificate could be in PEM or PKCS12 format.
 *
 * >>> This class uses external utility xmlling (usually found in libxml2-utils package) <<<
 * It is required to canonicalize XML before signing it, as required by standard.
 *
 * This is a basic example, which signes SOAP-ENV:Body part of the request. To change this see how
 * buildSignedInfo method works and update __doRequest accordingly (see the part where wsu:Id is set
 * on Body). Make sure that signed element has an wsu:Id attribute.
 *
 */
class SignedSoapClient extends SoapClient
{
    // `xmllint` path
    const XMLLINT_PATH          = '/usr/bin/xmllint';

    // namespaces defined by standard
    const WSU_NS    = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd';
    const WSSE_NS   = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd';
    const SOAP_NS   = 'http://schemas.xmlsoap.org/soap/envelope/';
    const DS_NS     = 'http://www.w3.org/2000/09/xmldsig#';

    protected $_ssl_options     = array();
    protected $_timeout         = 60;

    function __construct($wsdl, $options=array())
    {
        if (isset($options['ssl'])) {
            $this->_ssl_options = $options['ssl'];
            if (isset($this->_ssl_options['cert'])) {
                $certinfo = pathinfo($this->_ssl_options['cert']);
                if (in_array(strtolower($certinfo['extension']), array('p12', 'pfx')))
                    $this->_ssl_options['certtype'] = 'P12';
            }
        }
        if (isset($options['connection_timeout']) && intval($options['connection_timeout']))
            $this->_timeout = intval($options['connection_timeout']);
        return parent::__construct($wsdl, $options);
    }

    /**
     * Sample UUID function, based on random number or provided data
     *
     * @param mixed $data
     * @return string
     */
    function getUUID($data=null)
    {
        if ($data === null)
            $data = microtime() . uniqid();
        $id = md5($data);
        return sprintf('%08s-%04s-%04s-%04s-%012s', substr($id, 0, 8), substr($id, 8, 4), substr($id, 12, 4),
            substr(16, 4), substr($id, 20));
    }


    /**
     * XML canonicalization (using external utility)
     *
     * @param string $data
     * @return string
     */
    function canonicalizeXML($data)
    {
        $result = '';
        $fname = tempnam(sys_get_temp_dir(), 'ssc');
        $f = fopen($fname, 'w+');
        fwrite($f, $data);
        fclose($f);

        $f = popen(sprintf('%s --exc-c14n %s', self::XMLLINT_PATH, $fname), 'r');
        while ($read = fread($f, 4096))
            $result .= $read;
        pclose($f);
        unlink($fname);
        return $result;
    }

    /**
     * Canonicalize DOMNode instance and return result as string
     *
     * @param DOMNode $node
     * @return string
     */
    function canonicalizeNode($node)
    {
        $dom = new DOMDocument('1.0', 'utf-8');
        $dom->appendChild($dom->importNode($node, true));
        return $this->canonicalizeXML($dom->saveXML($dom->documentElement));
    }

    /**
     * Prepares SignedInfo DOMElement with required data
     *
     * $ids array should contain values of wsu:Id attribute of elements to be signed
     *
     * @param DOMDocument $dom
     * @param array $ids
     * @return DOMNode
     */
    function buildSignedInfo($dom, $ids)
    {
        $xp = new DOMXPath($dom);
        $xp->registerNamespace('SOAP-ENV', self::SOAP_NS);
        $xp->registerNamespace('wsu', self::WSU_NS);
        $xp->registerNamespace('wsse', self::WSSE_NS);
        $xp->registerNamespace('ds', self::DS_NS);

        $signedInfo = $dom->createElementNS(self::DS_NS, 'ds:SignedInfo');

        // canonicalization algorithm
        $method = $signedInfo->appendChild($dom->createElementNS(self::DS_NS, 'ds:CanonicalizationMethod'));
        $method->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');

        // signature algorithm
        $method = $signedInfo->appendChild($dom->createElementNS(self::DS_NS, 'ds:SignatureMethod'));
        $method->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1');

        foreach ($ids as $id) {
            // find a node and canonicalize it
            $nodes = $xp->query("//*[(@wsu:Id='{$id}')]");
            if ($nodes->length == 0)
                continue;
            $canonicalized = $this->canonicalizeNode($nodes->item(0));

            // create node Reference
            $reference = $signedInfo->appendChild($dom->createElementNS(self::DS_NS, 'ds:Reference'));
            $reference->setAttribute('URI', "#{$id}");
            $transforms = $reference->appendChild($dom->createElementNS(self::DS_NS, 'ds:Transforms'));
            $transform = $transforms->appendChild($dom->createElementNS(self::DS_NS, 'ds:Transform'));

            // mark node as canonicalized
            $transform->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');

            // and add a SHA1 digest
            $method = $reference->appendChild($dom->createElementNS(self::DS_NS, 'ds:DigestMethod'));
            $method->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
            $reference->appendChild($dom->createElementNS(self::DS_NS, 'ds:DigestValue', base64_encode(sha1($canonicalized, true))));
        }

        return $signedInfo;
    }

    /**
     * Prepares wsse:SecurityToken element based on public certificate
     * 
     * @param DOMDocument $dom
     * @param string $cert
     * @param string $certpasswd
     * @param resource $pkeyid
     * @param string $tokenId
     * @return DOMNode
     */
    function buildSecurityToken($dom, $cert, $certpasswd, &$pkeyid, &$tokenId)
    {
        $certinfo = pathinfo($cert);
        $cert = file_get_contents($cert);
        if (in_array(strtolower($certinfo['extension']), array('p12', 'pfx'))) {
            // for PKCS12 files
            openssl_pkcs12_read($cert, $certs, empty($this->_ssl_options['certpasswd']) ? '' : $this->_ssl_options['certpasswd']);
            $pkeyid = openssl_pkey_get_private($certs['pkey']);
            $pubcert = explode("\n", $certs['cert']);
            array_shift($pubcert);
            while (!trim(array_pop($pubcert))) {
            }
            array_walk($pubcert, 'trim');
            $pubcert = implode('', $pubcert);
            unset($certs);
        } else {
            // for PEM files
            $pkeyid = openssl_pkey_get_private($cert);
            $tempcert = openssl_x509_read($cert);
            openssl_x509_export($tempcert, $pubcert);
            openssl_x509_free($tempcert);
        }

        $tokenId = 'Security-Token-'.$this->getUUID($pubcert);

        // add public key reference to the token
        $token = $dom->createElementNS(self::WSSE_NS, 'wsse:BinarySecurityToken', $pubcert);
        $token->setAttribute('ValueType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3');
        $token->setAttribute('EncodingType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary');
        $token->setAttributeNS(self::WSU_NS, 'wsu:Id', $tokenId);
        return $token;
    }

    /**
     * Replace generic request with our own signed HTTPS request
     *
     * @param string $request
     * @param string $location
     * @param string $action
     * @param int $version
     * @return string
     */
    function __doRequest($request, $location, $action, $version)
    {
        // update request with security headers
        $dom = new DOMDocument('1.0', 'utf-8');
        $dom->loadXML($request);

        $xp = new DOMXPath($dom);
        $xp->registerNamespace('SOAP-ENV', self::SOAP_NS);

        // find or create SoapHeader
        $headernode	= $xp->query('/SOAP-ENV:Envelope/SOAP-ENV:Header')->item(0);
		$bodynode	= $xp->query('/SOAP-ENV:Envelope/SOAP-ENV:Body')->item(0);
		
        if(!$headernode){
            $headernode = $dom->documentElement->insertBefore($dom->createElementNS(self::SOAP_NS, 'SOAP-ENV:Header'), $bodynode);
		}

        /**
         * mark SOAP-ENV:Body with wsu:Id for signing 
         *
         * >> if you want to sign other elements - mark them on this step and provide id's on the later step
         *
         */
        $bodynode->setAttributeNS(self::WSU_NS, 'wsu:Id', 'reqBody');

        // prepare Security element
        $secNode = $headernode->appendChild($dom->createElementNS(self::WSSE_NS, 'wsse:Security'));

        // update with token data
        $secNode->appendChild($this->buildSecurityToken($dom, $this->_ssl_options['cert'],
            empty($this->_ssl_options['certpasswd']) ? '' : $this->_ssl_options['certpasswd'],
            $pkeyid, $tokenId));

        /**
         * create Signature element and build SignedInfo for elements with provided ids
         *
         * >> if you are signing other elements, add id's to the second argument of buildSignedInfo
         *
         */
        $signNode = $secNode->appendChild($dom->createElementNS(self::DS_NS, 'ds:Signature'));
        $signInfo = $signNode->appendChild($this->buildSignedInfo($dom, array('reqBody')));

        // now that SignedInfo is built, sign it actually
        openssl_sign($this->canonicalizeNode($signInfo), $signature, $pkeyid, OPENSSL_ALGO_SHA1);
        openssl_free_key($pkeyid);

        $signNode->appendChild($dom->createElementNS(self::DS_NS, 'ds:SignatureValue', base64_encode($signature)));
        $keyInfo = $signNode->appendChild($dom->createElementNS(self::DS_NS, 'ds:KeyInfo'));
        $secTokRef = $keyInfo->appendChild($dom->createElementNS(self::WSSE_NS, 'wsse:SecurityTokenReference'));
        $keyRef = $secTokRef->appendChild($dom->createElementNS(self::WSSE_NS, 'wsse:Reference'));
        $keyRef->setAttribute('URI', "#{$tokenId}");

        // convert new document to string
        $request = $dom->saveXML();

        // make our own HTTPRequest call with SSL certificate
        $options = array('timeout' => $this->_timeout);
        if ($this->_ssl_options)
            $options['ssl'] = $this->_ssl_options;
        $request = new HTTPRequest($location, HTTPRequest::METH_POST, $options);
        $request->setHeaders(array(
            'Content-Type' => 'application/soap+xml; charset=utf-8',
            'Content-Length' => mb_strlen($request, '8bit'),
            'SOAPAction' => $action
        ));
        $request->setBody($request);
        $request->send();
        return $request->getResponseBody();
    }
}
?>
