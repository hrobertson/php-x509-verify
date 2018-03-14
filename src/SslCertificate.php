<?php

namespace HRobertson\X509Verify;

class SslCertificate
{
    private $pem;
    private $der;

    /**
     * SslCertificate constructor.
     *
     * @param string $certificateData PEM format certificate
     */
    public function __construct($certificate)
    {
        if (!(bool)openssl_x509_read($certificate)) {
            throw new \InvalidArgumentException("Argument could not be parsed as a PEM encoded X.509 certificate.");
        }
        $this->pem = $certificate;
        return $this;
    }

    public function getAsPem()
    {
        return $this->pem;
    }

    /**
     * Get certificate in DER encoding
     *
     * @return string $derEncoded on success
     * @return bool false on failure
     */
    public function getAsDer()
    {
        if (!isset($this->der)) {
            $cert_split = preg_split('/(-----((BEGIN)|(END)) CERTIFICATE-----)/', $this->pem);
            $this->der = base64_decode($cert_split[1]);
        }
        return $this->der;
    }

    /**
     * Determine if one cert was used to sign another
     * Note that more than one CA cert can give a positive result, some certs
     * re-issue signing certs after having only changed the expiration dates.
     *
     * @param string $cert - PEM encoded cert
     * @param string $caCert - PEM encoded cert that possibly signed $cert
     * @return bool
     * @throws \ErrorException, \RuntimeException
     */
    public function isSignedBy(SslCertificate $otherCertificate)
    {
        if (!function_exists('openssl_pkey_get_public')) {
            throw new \RuntimeException('Need the openssl_pkey_get_public() function.');
        }
        if (!function_exists('openssl_public_decrypt')) {
            throw new \RuntimeException('Need the openssl_public_decrypt() function.');
        }
        if (!function_exists('hash')) {
            throw new \RuntimeException('Need the php hash() function.');
        }
        // Grab the encrypted signature from the der encoded cert.
        $encryptedSig = $this->getSignature();

        // Extract the public key from the ca cert, which is what has
        // been used to encrypt the signature in the cert.
        $pubKey = openssl_pkey_get_public($otherCertificate->getAsPem());
        if ($pubKey === false) {
            throw new \ErrorException('Failed to extract the public key from the other cert.');
        }
        // Attempt to decrypt the encrypted signature using the CA's public
        // key, returning the decrypted signature in $decryptedSig.  If
        // it can't be decrypted, this ca was not used to sign it for sure...
        $rc = openssl_public_decrypt($encryptedSig, $decryptedSig, $pubKey);
        if ($rc === false) {
            return false;
        }
        // We now have the decrypted signature, which is der encoded
        // asn1 data containing the signature algorithm and signature hash.
        // Now we need what was originally hashed by the issuer, which is
        // the original DER encoded certificate without the issuer and
        // signature information.
        $origCert = $this->stripSignerAsn();

        // Get the oid of the signature hash algorithm, which is required
        // to generate our own hash of the original cert.  This hash is
        // what will be compared to the issuers hash.
        $oid = $this->getSignatureAlgorithmOid($decryptedSig);
        switch ($oid) {
            case '1.2.840.113549.2.2':
                $algo = 'md2';
                break;
            case '1.2.840.113549.2.4':
                $algo = 'md4';
                break;
            case '1.2.840.113549.2.5':
                $algo = 'md5';
                break;
            case '1.3.14.3.2.18':
                $algo = 'sha';
                break;
            case '1.3.14.3.2.26':
                $algo = 'sha1';
                break;
            case '2.16.840.1.101.3.4.2.1':
                $algo = 'sha256';
                break;
            case '2.16.840.1.101.3.4.2.2':
                $algo = 'sha384';
                break;
            case '2.16.840.1.101.3.4.2.3':
                $algo = 'sha512';
                break;
            default:
                throw new \ErrorException('Unknown signature hash algorithm oid: ' . $oid);
                break;
        }
        // Get the issuer generated hash from the decrypted signature.
        $decryptedHash = $this->getSignatureHash($decryptedSig);
        // Ok, hash the original unsigned cert with the same algorithm
        // and if it matches $decryptedHash we have a winner.
        $certHash = hash($algo, $origCert);
        return ($decryptedHash === $certHash);
    }

    /**
     * Extract signature from DER encoded cert.
     * Expects x509 DER encoded certificate consisting of a section container
     * containing 2 sections and a bitstream.  The bitstream contains the
     * original encrypted signature, encrypted by the public key of the issuing
     * signer.
     *
     * @return string on success
     * @throws \ErrorException
     */
    private function getSignature()
    {
        $der = $this->getAsDer();
        // skip container sequence
        $der = substr($der, 4);
        // now burn through two sequences and the return the final bitstream
        while (strlen($der) > 1) {
            $class = ord($der[0]);
            switch ($class) {
                // BITSTREAM
                case 0x03:
                    $len = ord($der[1]);
                    $bytes = 0;
                    if ($len & 0x80) {
                        $bytes = $len & 0x0f;
                        $len = 0;
                        for ($i = 0; $i < $bytes; $i++) {
                            $len = ($len << 8) | ord($der[$i + 2]);
                        }
                    }
                    return substr($der, 3 + $bytes, $len);
                    break;
                // SEQUENCE
                case 0x30:
                    $len = ord($der[1]);
                    $bytes = 0;
                    if ($len & 0x80) {
                        $bytes = $len & 0x0f;
                        $len = 0;
                        for ($i = 0; $i < $bytes; $i++) {
                            $len = ($len << 8) | ord($der[$i + 2]);
                        }
                    }
                    $der = substr($der, 2 + $bytes + $len);
                    break;
                default:
                    throw new \ErrorException("Could not extract signature");
                    break;
            }
        }
        return false;
    }

    /**
     * Obtain DER cert with issuer and signature sections stripped.
     *
     * @return string $der on success
     * @return bool false on failures.
     */
    private function stripSignerAsn()
    {
        $der = $this->getAsDer();
        $bit = 4;
        $len = ord($der[($bit + 1)]);
        if ($len & 0x80) {
            $bytes = $len & 0x0f;
            $len = 0;
            for ($i = 0; $i < $bytes; $i++) {
                $len = ($len << 8) | ord($der[$bit + $i + 2]);
            }
        }
        return substr($der, 4, $len + 4);
    }

    /**
     * Get signature algorithm oid from der encoded signature data.
     * Expects decrypted signature data from a certificate in der format.
     * This ASN1 data should contain the following structure:
     * SEQUENCE
     *    SEQUENCE
     *       OID    (signature algorithm)
     *       NULL
     * OCTET STRING (signature hash)
     *
     * @return bool false on failures
     * @return string oid
     * @throws \ErrorException
     */
    private function getSignatureAlgorithmOid($derSignature)
    {
        $der = $derSignature;
        $bit_seq1 = 0;
        $bit_seq2 = 2;
        $bit_oid = 4;
        if (ord($der[$bit_seq1]) !== 0x30) {
            throw new \ErrorException('Invalid DER passed to getSignatureAlgorithmOid()');
        }
        if (ord($der[$bit_seq2]) !== 0x30) {
            throw new \ErrorException('Invalid DER passed to getSignatureAlgorithmOid()');
        }
        if (ord($der[$bit_oid]) !== 0x06) {
            throw new \ErrorException('Invalid DER passed to getSignatureAlgorithmOid');
        }
        // strip out what we don't need and get the oid
        $der = substr($der, $bit_oid);
        // Get the oid
        $len = ord($der[1]);
        $bytes = 0;
        if ($len & 0x80) {
            $bytes = $len & 0x0f;
            $len = 0;
            for ($i = 0; $i < $bytes; $i++) {
                $len = ($len << 8) | ord($der[$i + 2]);
            }
        }
        $oid_data = substr($der, 2 + $bytes, $len);
        // Unpack the OID
        $oid = floor(ord($oid_data[0]) / 40);
        $oid .= '.' . ord($oid_data[0]) % 40;
        $value = 0;
        $i = 1;
        while ($i < strlen($oid_data)) {
            $value = $value << 7;
            $value = $value | (ord($oid_data[$i]) & 0x7f);
            if (!(ord($oid_data[$i]) & 0x80)) {
                $oid .= '.' . $value;
                $value = 0;
            }
            $i++;
        }
        return $oid;
    }

    /**
     * Get signature hash from der encoded signature data.
     * Expects decrypted signature data from a certificate in der format.
     * This ASN1 data should contain the following structure:
     * SEQUENCE
     *    SEQUENCE
     *       OID    (signature algorithm)
     *       NULL
     * OCTET STRING (signature hash)
     *
     * @return bool false on failures
     * @return string hash
     * @throws \InvalidArgumentException
     */
    private function getSignatureHash($signature)
    {
        $der = $signature;
        if (ord($der[0]) !== 0x30) {
            throw new \InvalidArgumentException('Invalid DER signature');
        }
        // strip out the container sequence
        $der = substr($der, 2);
        if (ord($der[0]) !== 0x30) {
            throw new \InvalidArgumentException('Invalid DER signature');
        }
        // Get the length of the first sequence so we can strip it out.
        $len = ord($der[1]);
        $bytes = 0;
        if ($len & 0x80) {
            $bytes = $len & 0x0f;
            $len = 0;
            for ($i = 0; $i < $bytes; $i++) {
                $len = ($len << 8) | ord($der[$i + 2]);
            }
        }
        $der = substr($der, 2 + $bytes + $len);
        // Now we should have an octet string
        if (ord($der[0]) !== 0x04) {
            throw new \InvalidArgumentException('Invalid DER signature');
        }
        $len = ord($der[1]);
        $bytes = 0;
        if ($len & 0x80) {
            $bytes = $len & 0x0f;
            $len = 0;
            for ($i = 0; $i < $bytes; $i++) {
                $len = ($len << 8) | ord($der[$i + 2]);
            }
        }
        return bin2hex(substr($der, 2 + $bytes, $len));
    }
}