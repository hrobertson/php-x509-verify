<?php

namespace HRobertson\X509Verify\Test;

use HRobertson\X509Verify\DerElement;
use PHPUnit\Framework\TestCase;

final class DerElementTest extends TestCase
{
    private $cert;

    public function setUp()
    {
        $this->cert = base64_decode("MIICFjCCAX8CCQDv3XixVkYLGzANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJHQjETMBEGA1UECAwKU29tZS1TdGF0ZTESMBAGA1UECgwJSGFtaXNoIENBMRswGQYDVQQDDBJIYW1pc2ggQ0EgSXNzdWVyIDEwHhcNMTgwMzEzMTUxMDQzWhcNMTgwNDEyMTUxMDQzWjBMMQswCQYDVQQGEwJHQjETMBEGA1UECAwKU29tZS1TdGF0ZTESMBAGA1UECgwJVGVzdCBTaXRlMRQwEgYDVQQDDAt0ZXN0MTIzLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAu7ppgsXqSjsaMC9sukV7q/ubFPTr929oYqojYnsseHgoSy3tmtcLyw6iT3kibD+rig0Xi+GcmNsh5Rpw3u6Ije3HanGFsIzKBwtBQ9y9QIGcIeDuUMSagp5aB7xoLETlG1X7sT5HX/S7i2BAuY4TgkOhv393FbupnWWuT5tjYEsCAwEAATANBgkqhkiG9w0BAQsFAAOBgQAOdx8UZ4X/z+WUlcqcREcwtPQ7zb1zGHZJUJ7aQSFAXAXesqxTJbl51wFRxNb0qjnIhju3CAGKhnNYb8uiMZi8/YNGNV9B+YLRr48qIgIBITtnxjokOTZ4ky/dJxxxMLMJ6EJ8pla/1TvzZlxizyqEmZeOKG5LjpyfSt59Dry5Og==");
    }

    public function testGetClass()
    {
        $der = new DerElement($this->cert);
        $this->assertEquals(0, $der->getClass());
    }

    public function testIsConstructed()
    {
        $der = new DerElement($this->cert);
        $this->assertTrue($der->isConstructed());
    }

    public function testGetTagNumber()
    {
        $der = new DerElement($this->cert);
        $this->assertEquals(16, $der->getTagNumber());
    }

    public function testGetContent()
    {
        $der = new DerElement($this->cert);
        $contents = $der->getContent();
        $this->assertCount(3, $contents);
    }
}
