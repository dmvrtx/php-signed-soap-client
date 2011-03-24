<?php
/**
 * Расширение SOAP клиента с подписью сообщений сертификатом и HTTPS соединением
 * $Id$
 */

/**
 * Класс SOAP клиента с подписью сообщений и HTTPS-соединением
 *
 * Настройки SSL для соединения задаются при создании класса в массиве options в виде массива,
 * аналогично опциям HTTP запроса, например:
 *    $client = new SignedSoapClient('https://example.com?wsdl', array('ssl' => array('cert' => '/file',
 *          'certpasswd' => 'password')));
 *
 * Файл сертификата может быть как в PEM так и в PKCS12 формате.
 *
 * (!) Для канонизации XML используется утилита xmllint из пакета libxml2-utils.
 *
 * Данный вариант подписывает только SOAP-ENV:Body часть запроса, однако легко настраивается на подпись
 * и любых других элементов (см. buildSignedInfo), у которых должен быть прописан атрибут wsu:Id.
 */
class SignedSoapClient extends SoapClient
{
    // путь к xmllint
    const XMLLINT_PATH          = '/usr/bin/xmllint';

    // используемые namespace
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
     * Возвращает UUID случайный или на основе данных
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
     * Канонизация XML
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
     * Возвращает строку с канонизированной записью DOMNode
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
     * Строит информацию о подписываемых элементах
     *
     * Вторым параметром идет список значений wsu:Id подписываемых элементов
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
        // алгоритм канонизации
        $method = $signedInfo->appendChild($dom->createElementNS(self::DS_NS, 'ds:CanonicalizationMethod'));
        $method->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
        // алгоритм подписи
        $method = $signedInfo->appendChild($dom->createElementNS(self::DS_NS, 'ds:SignatureMethod'));
        $method->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#rsa-sha1');

        foreach ($ids as $id) {
            // найдём узел и его каноническую запись
            $nodes = $xp->query("//*[(@wsu:Id='{$id}')]");
            if ($nodes->length == 0)
                continue;
            $canonicalized = $this->canonicalizeNode($nodes->item(0));

            // создадим Reference для ноды
            $reference = $signedInfo->appendChild($dom->createElementNS(self::DS_NS, 'ds:Reference'));
            $reference->setAttribute('URI', "#{$id}");
            $transforms = $reference->appendChild($dom->createElementNS(self::DS_NS, 'ds:Transforms'));
            $transform = $transforms->appendChild($dom->createElementNS(self::DS_NS, 'ds:Transform'));
            // укажем, что провели канонизацию
            $transform->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
            // и сделаем дайджест с помощью SHA1
            $method = $reference->appendChild($dom->createElementNS(self::DS_NS, 'ds:DigestMethod'));
            $method->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#sha1');
            $reference->appendChild($dom->createElementNS(self::DS_NS, 'ds:DigestValue', base64_encode(sha1($canonicalized, true))));
        }

        return $signedInfo;
    }

    /**
     * Создает элемент wsse:SecurityToken на основе сертификата, задавая в pkeyid ресурс приватного ключа
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
            // читаем pkcs12
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
            // читаем pem
            $pkeyid = openssl_pkey_get_private($cert);
            $tempcert = openssl_x509_read($cert);
            openssl_x509_export($tempcert, $pubcert);
            openssl_x509_free($tempcert);
        }

        $tokenId = 'Security-Token-'.$this->getUUID($pubcert);

        // добавим ссылку на ключ в заголовок
        $token = $dom->createElementNS(self::WSSE_NS, 'wsse:BinarySecurityToken', $pubcert);
        $token->setAttribute('ValueType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3');
        $token->setAttribute('EncodingType', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary');
        $token->setAttributeNS(self::WSU_NS, 'wsu:Id', $tokenId);
        return $token;
    }

    /**
     * Подмена запроса 
     *
     * @param string $request
     * @param string $location
     * @param string $action
     * @param int $version
     * @return string
     */
    function __doRequest($request, $location, $action, $version)
    {
        // проведём добавление нужных заголовков
        $dom = new DOMDocument('1.0', 'utf-8');
        $dom->loadXML($request);

        $xp = new DOMXPath($dom);
        $xp->registerNamespace('SOAP-ENV', self::SOAP_NS);

        // найдём узел SoapHeader, а если его нет - создадим
        $headernode = $xp->query('/SOAP-ENV:Envelope/SOAP-ENV:Header')->item(0);
        if (!$headernode)
            $headernode = $dom->documentElement->insertBefore($dom->createElementNS(self::SOAP_NS, 'SOAP-ENV:Header'), $bodynode);

        // и проставим wsu:Id у тела запроса
        $bodynode = $xp->query('/SOAP-ENV:Envelope/SOAP-ENV:Body')->item(0);
        $bodynode->setAttributeNS(self::WSU_NS, 'wsu:Id', 'reqBody');

        // добавим элемент wsse:Security, в который будет завёрнута информация о подписи
        $secNode = $headernode->appendChild($dom->createElementNS(self::WSSE_NS, 'wsse:Security'));

        // добавляем ссылку на ключ
        $secNode->appendChild($this->buildSecurityToken($dom, $this->_ssl_options['cert'],
            empty($this->_ssl_options['certpasswd']) ? '' : $this->_ssl_options['certpasswd'],
            $pkeyid, $tokenId));

        // ссылка на подписываемый элемент
        $signNode = $secNode->appendChild($dom->createElementNS(self::DS_NS, 'ds:Signature'));
        $signInfo = $signNode->appendChild($this->buildSignedInfo($dom, array('reqBody')));

        // и сама подпись
        openssl_sign($this->canonicalizeNode($signInfo), $signature, $pkeyid, OPENSSL_ALGO_SHA1);
        openssl_free_key($pkeyid);

        $signNode->appendChild($dom->createElementNS(self::DS_NS, 'ds:SignatureValue', base64_encode($signature)));
        $keyInfo = $signNode->appendChild($dom->createElementNS(self::DS_NS, 'ds:KeyInfo'));
        $secTokRef = $keyInfo->appendChild($dom->createElementNS(self::WSSE_NS, 'wsse:SecurityTokenReference'));
        $keyRef = $secTokRef->appendChild($dom->createElementNS(self::WSSE_NS, 'wsse:Reference'));
        $keyRef->setAttribute('URI', "#{$tokenId}");

        $request = $dom->saveXML(); 
        
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
