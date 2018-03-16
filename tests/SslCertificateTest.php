<?php

namespace HRobertson\X509Verify\Test;

use HRobertson\X509Verify\SslCertificate;
use PHPUnit\Framework\TestCase;

class SslCertificateTest extends TestCase
{
    private $leafCert = [
        'pem' => "-----BEGIN CERTIFICATE-----\nMIICFjCCAX8CCQDv3XixVkYLGzANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJHQjETMBEGA1UECAwKU29tZS1TdGF0ZTESMBAGA1UECgwJSGFtaXNoIENBMRswGQYDVQQDDBJIYW1pc2ggQ0EgSXNzdWVyIDEwHhcNMTgwMzEzMTUxMDQzWhcNMTgwNDEyMTUxMDQzWjBMMQswCQYDVQQGEwJHQjETMBEGA1UECAwKU29tZS1TdGF0ZTESMBAGA1UECgwJVGVzdCBTaXRlMRQwEgYDVQQDDAt0ZXN0MTIzLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAu7ppgsXqSjsaMC9sukV7q/ubFPTr929oYqojYnsseHgoSy3tmtcLyw6iT3kibD+rig0Xi+GcmNsh5Rpw3u6Ije3HanGFsIzKBwtBQ9y9QIGcIeDuUMSagp5aB7xoLETlG1X7sT5HX/S7i2BAuY4TgkOhv393FbupnWWuT5tjYEsCAwEAATANBgkqhkiG9w0BAQsFAAOBgQAOdx8UZ4X/z+WUlcqcREcwtPQ7zb1zGHZJUJ7aQSFAXAXesqxTJbl51wFRxNb0qjnIhju3CAGKhnNYb8uiMZi8/YNGNV9B+YLRr48qIgIBITtnxjokOTZ4ky/dJxxxMLMJ6EJ8pla/1TvzZlxizyqEmZeOKG5LjpyfSt59Dry5Og==\n-----END CERTIFICATE-----",
        'signature' => "0e771f146785ffcfe59495ca9c444730b4f43bcdbd73187649509eda4121405c05deb2ac5325b979d70151c4d6f4aa39c8863bb708018a8673586fcba23198bcfd8346355f41f982d1af8f2a220201213b67c63a24393678932fdd271c7130b309e8427ca656bfd53bf3665c62cf2a8499978e286e4b8e9c9f4ade7d0ebcb93a",
        'signatureAlgorithm' => 'sha256',
        'tbsCert' => "3082017f020900efdd78b156460b1b300d06092a864886f70d01010b05003053310b30090603550406130247423113301106035504080c0a536f6d652d537461746531123010060355040a0c0948616d697368204341311b301906035504030c1248616d697368204341204973737565722031301e170d3138303331333135313034335a170d3138303431323135313034335a304c310b30090603550406130247423113301106035504080c0a536f6d652d537461746531123010060355040a0c095465737420536974653114301206035504030c0b746573743132332e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100bbba6982c5ea4a3b1a302f6cba457babfb9b14f4ebf76f6862aa23627b2c7878284b2ded9ad70bcb0ea24f79226c3fab8a0d178be19c98db21e51a70deee888dedc76a7185b08cca070b4143dcbd40819c21e0ee50c49a829e5a07bc682c44e51b55fbb13e475ff4bb8b6040b98e138243a1bf7f7715bba99d65ae4f9b63604b0203010001"
    ];

    private $issuerCert = [
        'pem' => "-----BEGIN CERTIFICATE-----\nMIICFDCCAX0CCQCzcbZthRZ4djANBgkqhkiG9w0BAQsFADBKMQswCQYDVQQGEwJHQjETMBEGA1UECAwKU29tZS1TdGF0ZTESMBAGA1UECgwJSGFtaXNoIENBMRIwEAYDVQQDDAlIYW1pc2ggQ0EwHhcNMTgwMzEzMTUwOTA1WhcNMTgwNDEyMTUwOTA1WjBTMQswCQYDVQQGEwJHQjETMBEGA1UECAwKU29tZS1TdGF0ZTESMBAGA1UECgwJSGFtaXNoIENBMRswGQYDVQQDDBJIYW1pc2ggQ0EgSXNzdWVyIDEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALJiC44pSeVBR4ReS2RVBE322erpxnshPijC0dpHuMt/3fcZoEBow7W9/v2oBU11+ZwgMdh6RPt57yFYEtFa/j9of0YErf9lun8Slj2QVzn9oZLnJPswp4Hox2O+dRwH+Q0YjtNPhPouGJfKTfRwpbUZ1SpX/keyeiyvLCj6BKsdAgMBAAEwDQYJKoZIhvcNAQELBQADgYEAih35Gt5+6zynXWJLObLhC6idhnGEvWNTwrNefgyKStA5hZOsjzyetihrJ/qFl8EYjL4BVaegM888KPPNu/kfFD6VsWXDgL6fxi0I7illemVqc5x8G/IrXGOn158C5G1to5GuNapxAQ3HYmhqAOlsoagXPyead+v9XCCNuUDmWkg=\n-----END CERTIFICATE-----"
    ];

    private $notIssuerCert = [
        'pem' => "-----BEGIN CERTIFICATE-----\nMIICAzCCAWwCCQC2LxpR2s25ODANBgkqhkiG9w0BAQsFADA3MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTETMBEGA1UECgwKSGFtaXNoIENBMjAeFw0xODAzMTMxNTQ2NTBaFw0xODA0MTIxNTQ2NTBaMFUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMRMwEQYDVQQKDApIYW1pc2ggQ0EyMRwwGgYDVQQDDBNIYW1pc2ggQ0EyIElzc3VlciAxMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVP9WYYqe4tOEvo1ueiUouiJ4H3RYt+aHaGjVeoBuomJtDWDeji1kmE+YBB6gxk8LvyNghe8PeWzElwnEp2Cew1W9o+2iQkjv3SPuFJfEMwCTvYhev5tOClggynXEx7pXFdVKS8v7pmVkL79cKKsF6nrefMRuThOXtrsrykBCbPwIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAPRPkNBX6PEcPy5sTOYK29H2eiBPyK2CfXgeM09mkgn08blIL387+qJQckI5pbFGR6c9S8EAZIpsmxgWVH66cJlrm/vj1WTuqFuhQ9soynpf/XfOwI4wYriqal/nhvN71/360G/7VmzeNyhdjf6LJRKChBcLIGFQuRtg8734AGmJ\n-----END CERTIFICATE-----"
    ];

    public function testGetSignature()
    {
        $cert = new SslCertificate($this->leafCert['pem']);
        $sig = $cert->getSignature();
        $hex = bin2hex($sig);
        $this->assertEquals($this->leafCert['signature'], $hex);
    }

    public function testGetTbsCertificate()
    {
        $cert = new SslCertificate($this->leafCert['pem']);
        $cert = $cert->getTbsCertificate();
        $hex = bin2hex($cert);
        $this->assertEquals($this->leafCert['tbsCert'], $hex);
    }

    public function testGetSignatureAlgorithm()
    {
        $leafCert = new SslCertificate($this->leafCert['pem']);
        $encryptedSig = $leafCert->getSignature();

        $issuerCert = new SslCertificate($this->issuerCert['pem']);

        $decryptedSig = SslCertificate::decryptSignature($encryptedSig, $issuerCert);
        $algorithm = SslCertificate::getSignatureAlgorithm($decryptedSig);
        $this->assertEquals('sha256', $algorithm);
    }

    public function testIsSignedBy()
    {
        $leafCert = new SslCertificate($this->leafCert['pem']);
        $issuerCert = new SslCertificate($this->issuerCert['pem']);
        $notIssuerCert = new SslCertificate($this->notIssuerCert['pem']);

        $this->assertTrue($leafCert->isSignedBy($issuerCert));
        $this->assertFalse($leafCert->isSignedBy($leafCert));
        $this->assertFalse($leafCert->isSignedBy($notIssuerCert));
    }
}
