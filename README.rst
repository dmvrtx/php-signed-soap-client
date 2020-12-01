=======
PHP SoapClient with SOAP Message Security
=======


Requirements
------------

- PHP compiled with SOAP support
- xmllint_ utility (ubuntu/debian has it in libxml2-utils package)
- HTTPRequest class provided by `pecl_http` extension

.. _xmllint: http://xmlsoft.org/xmllint.html


Usage 
-----

This class supports `SOAP Message Security`_ standard.

.. _`SOAP Message Security`: http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0.pdf

You should set certificate (in PFX or PKCS7 format) while initializing class. Other
HTTP options, identical to HTTPRequest_ class request options are accepted too::

        $client = new SignedSoapClient(
                'https://example.com?wsdl', 
                array(
                        'ssl' => array(
                                'cert' => '/file',
                                'certpasswd' => 'password'
                                )
                        )
        );

.. _HTTPRequest: http://php.net/HTTPRequest

Class signes SOAP-ENV:Body part of the message by default, this behaviour can be changed
in ``buildSignedInfo`` method.
