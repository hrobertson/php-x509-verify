Determine if an X.509 certificate is the signer of another.

This is based on and uses parts of Mike Green's script from http://badpenguins.com/source/misc/isCertSigner.php?viewSource
## Requirements

`PHP 7.0` or `PHP 5.6`

## Installation

The preferred way to install this library is via [Composer][1]:

```bash
$ composer require hrobertson/x509-verify
```

## Usage

```php
use HRobertson\X509Verify\SslCertificate;

$leafCertificate = new SslCertificate(file_get_contents('example.com.pem'));
$issuerCertificate = new SslCertificate(file_get_contents('intermediate.pem'));

$leafCertificate->isSignedBy($issuerCertificate); // returns true if $leafCertificate is signed by $issuerCertificate
```

## Licence

As stipulated by Mike Green, the author of the original script, this software is licenced under the GPLv2. Please see [License File](LICENSE.md) for more information.

[1]: https://getcomposer.org/