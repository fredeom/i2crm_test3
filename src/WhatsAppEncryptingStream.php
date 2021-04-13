<?php

use Psr\Http\Message\StreamInterface;

require_once(__DIR__ . '/CipherKeyGenerator.php');

class WhatsAppEncryptingStream implements StreamInterface {

  private $buffer = '';
  private $sideCarBuffer = '';
  private $keys;
  private $stream;

  public function __construct(StreamInterface $stream, CipherKeyGenerator $keys) {
    $this->stream = $stream;
    $this->keys = $keys;

    $this->encrypt();
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
    $this->sideCarBuffer = '';
  }

  public function detach() {
    $this->buffer = '';
    $this->sideCarBuffer = '';
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

  private function signIvEncWithMacKey($text) {
    return substr(hash_hmac("sha256", $this->keys->getIv() . $text, $this->keys->getMacKey(), true), 0, 10);
  }

  private function signWithMacKey($text) {
    return substr(hash_hmac("sha256", $text, $this->keys->getMacKey(), true), 0, 10);
  }

  private function encrypt() {
    if ($this->stream->eof()) {
      return;
    }

    $length = 64 * 1024;
    $plainText = '';
    do {
        $plainText .= $this->stream->read($length);
    } while (!$this->stream->eof());

    $this->buffer = openssl_encrypt(
      $plainText,
      "AES-256-CBC",
      $this->keys->getCipherKey(),
      OPENSSL_RAW_DATA,
      $this->keys->getIv()
    );

    $this->buffer .= $this->signIvEncWithMacKey($this->buffer);

    $text = $plainText;
    //$text = $this->buffer;

    if (in_array($this->keys->getMediaType(), ["VIDEO", "AUDIO"])) {
      $textLen = strlen($text);
      $i = 0;
      do {
        $block = substr($text, $i, $length + 16);
        $this->sideCarBuffer .= $this->signWithMacKey($block);
        $i += $length;
      } while ($i < $textLen);
    }
  }

  public function getSidecar() {
    if (in_array($this->keys->getMediaType(), ["VIDEO", "AUDIO"])) {
      return $this->sideCarBuffer;
    }
  }
} 
 
?>