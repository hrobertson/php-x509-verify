<?php

namespace HRobertson\X509Verify;

class DerElement
{
    private $bytes;
    private $tagNumber;
    private $lengthStart;
    private $contentLength;
    private $contentStart;

    /**
     * DerElement constructor.
     *
     * @param string $bytes DER encoded binary string
     */
    public function __construct($bytes)
    {
        $this->bytes = $bytes;
    }

    /**
     * @return int ASN.1 Type Class
     *
     */
    public function getClass()
    {
        return ord($this->bytes[0]) >> 6;
    }

    /**
     * @return bool True if Constructed, False if Primitive
     */
    public function isConstructed()
    {
        return (bool) ((ord($this->bytes[0]) & 0x20) >> 5);
    }

    /**
     * @return int ASN.1 Tag number
     */
    public function getTagNumber()
    {
        if (!isset($this->tagNumber)) {
            $number = ord($this->bytes[0]) & 0x1F;
            if ($number === 0x1F) {
                $number = 0x00;
                for ( $i = 1; $byte = ord($this->bytes[$i]); ++$i ) {
                    $this->lengthStart = $i + 1;
                    $bits = $byte & 0x7F;
                    $number = $number | $bits;
                    if ($byte & 0x80 === 0x80) {
                        $number = $number << 8;
                    } else {
                        break;
                    }
                }
            } else {
                $this->lengthStart = 1;
            }
            $this->tagNumber = $number;
        }
        return $this->tagNumber;
    }

    /**
     * @return DerElement[] Constructed elements will return an array of DerElement
     * @return string Primitive elements will return a binary string
     * @return null Elements with no content length will return null
     * @throws \ErrorException If data is not a DER encoded object
     * @throws \UnexpectedValueException
     */
    public function getContent()
    {
        if ($this->getContentLength() === 0) {
            return null;
        }
        if ($this->isConstructed()) {
            return self::getSequence($this);
        } else {
            if ($this->getTagNumber() === 0x03) {
                // BIT STRING
                // First byte specifies the number of unused bits in the last content byte
                if (bindec(substr($this->bytes, $this->contentStart, 1)) === 0) {
                    return substr($this->bytes, $this->contentStart + 1, $this->getContentLength() - 1);
                } else {
                    throw new \UnexpectedValueException("Bit Strings with incomplete bytes not supported");
                }
            }
            return substr($this->bytes, $this->contentStart, $this->getContentLength());
        }
    }

    /**
     * @return int Number of bytes of content
     * @throws \ErrorException If data is not a DER encoded object
     */
    private function getContentLength()
    {
        if (!isset($this->contentLength)) {
            if (!isset($this->lengthStart)) {
                $this->getTagNumber();
            }
            $byte = ord($this->bytes[$this->lengthStart]);
            $bit8 = $byte >> 7;
            $bits = $byte & 0x7F;

            if ($bit8 === 0) {
                $this->contentStart = $this->lengthStart + 1;
                $this->contentLength = $bits;
            } elseif ($bits === 0) {
                // Indefinite
                throw new \ErrorException("Not a DER encoded object: Indefinite content length");
            } elseif ($bits === 0x7F) {
                throw new \ErrorException("Not a DER encoded object: Invalid content length");
            } else {
                $this->contentStart = $this->lengthStart + $bits + 1;
                $lengthBytes = substr($this->bytes, $this->lengthStart + 1, $bits );
                $x = 8 - strlen($lengthBytes);
                $padding = str_repeat(chr(hexdec(0x00)), $x);
                $this->contentLength = unpack("J", $padding . $lengthBytes)[1];
            }
            $this->bytes = substr($this->bytes, 0, $this->contentStart + $this->contentLength );
        }
        return $this->contentLength;
    }

    private function getContentStart()
    {
        if (!isset($this->contentStart)) {
            $this->getContentLength();
        }
        return $this->contentStart;
    }

    private function getTotalLength()
    {
        return $this->getContentStart() + $this->getContentLength();
    }

    /**
     * @return string Whole object including header as binary string
     */
    public function getAsBytes()
    {
        return $this->bytes;
    }

    /**
     * @return string Content as binary string
     */
    public function getRawContent()
    {
        if ($this->getContentLength() === 0) {
            return null;
        }
        return substr($this->bytes, $this->contentStart, $this->getContentLength());
    }

    private static function getSequence(DerElement $element)
    {
        $sequence = array();
        $bytes = $element->getRawContent();

        while (strlen($bytes) > 0) {
            $o = new DerElement($bytes);
            $sequence[] = $o;
            $len = $o->getTotalLength();
            $bytes = substr($bytes, $len);
        }

        return $sequence;
    }
}