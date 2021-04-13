<?php

use Psr\Http\Message\StreamInterface;

require_once(__DIR__ . '/CipherKeyGenerator.php');

class WhatsAppDecryptingStream implements StreamInterface {
  
  private $buffer = '';
  private $keys;
  private $stream;

  public function __construct(StreamInterface $stream, CipherKeyGenerator $keys) {
    $this->stream = $stream;
    $this->keys = $keys;

    $this->decrypt();
  }

  public function getSize() {
    throw new \BadMethodCallException('Not implemented');
  }

  public function isWritable() {
    return false;
  }

  public function __toString() {
    return $this->getContents();
  }
  public function close() {
    $this->buffer = '';
  }
  public function detach() {
    $this->buffer = '';
  }
  public function tell() {
    throw new \BadMethodCallException('Not implemented');
  }
  
  public function isSeekable() {
    return false;
  }

  public function seek($offset, $whence = SEEK_SET) {
    throw new \BadMethodCallException('Not implemented');
  }

  public function rewind() {
    throw new \BadMethodCallException('Not implemented');
  }

  public function write($string) {
    throw new \BadMethodCallException('Not implemented');
  }

  public function isReadable() {
    return true;
  }

  public function getContents() {
    return $this->buffer;
  }

  public function getMetadata($key = null) {
    return null;
  }

  public function eof() {
    return $this->buffer == '';
  }

  public function read($length = -1) {
    if ($length == -1) {
      $length = strlen($this->buffer);
    }
    $data = substr($this->buffer, 0, $length);
    $this->buffer = substr($this->buffer, $length);
    return $data ? $data : '';
  }

  private function isSignatureValid($file, $mac) {
    return substr($mac, 0, 10) == substr(hash_hmac("sha256", $this->keys->getIv() . $file, $this->keys->getMacKey(), true), 0, 10);
  }

  private function decrypt() {
    if ($this->stream->eof()) {
      return;
    }

    $length = 1024 * 1024;
    $plainText = '';
    do {
        $plainText .= $this->stream->read($length);
    } while (!$this->stream->eof());

    $fileAndMac = str_split($plainText, strlen($plainText) - 10);

    if (!$this->isSignatureValid($fileAndMac[0], $fileAndMac[1])) {
      throw new \BadMethodCallException('Validation failed');
    }

    $this->buffer = openssl_decrypt(
      $fileAndMac[0],
      "AES-256-CBC",
      $this->keys->getCipherKey(),
      OPENSSL_RAW_DATA,
      $this->keys->getIv()
    );
  }
}

?>