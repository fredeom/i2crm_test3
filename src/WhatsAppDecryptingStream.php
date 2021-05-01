<?php

use Psr\Http\Message\StreamInterface;

require_once(__DIR__ . '/CipherKeyGenerator.php');

class WhatsAppDecryptingStream implements StreamInterface {

  const BLOCK_SIZE = 32;

  private $buffer = '';
  private $cipherBuffer = '';
  private $keys;
  private $stream;

  public function __construct(StreamInterface $stream, CipherKeyGenerator $keys) {
    $this->stream = $stream;
    $this->keys = $keys;

    $this->initializeHash();
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
    $this->cipherBuffer = '';
    $this->stream->close();
  }
  public function detach() {
    $this->buffer = '';
    $this->cipherBuffer = '';
    return $this->stream->detach();
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
    return $this->buffer === '' && $this->cipherBuffer === '' && $this->stream->eof();
  }

  public function read($length) {
    if ($length > strlen($this->buffer)) {
      $this->buffer .= $this->decryptBlock(
          self::BLOCK_SIZE * ceil(($length - strlen($this->buffer)) / self::BLOCK_SIZE)
      );
    }
    $data = substr($this->buffer, 0, $length);
    $this->buffer = substr($this->buffer, $length);
    return $data ? $data : '';
  }

  private function isSignatureValid($hash, $mac) {
    return substr($mac, 0, 10) == substr($hash, 0, 10);
  }

  private function decryptBlock($length) {
    if ($this->cipherBuffer === '' && $this->stream->eof()) {
      return '';
    }

    $cipherText = $this->cipherBuffer;
    while (strlen($cipherText) < $length && !$this->stream->eof()) {
        $cipherText .= $this->stream->read($length - strlen($cipherText));
    }

    $options = OPENSSL_RAW_DATA;
    $this->cipherBuffer = $this->stream->read(self::BLOCK_SIZE + 10);
    if (!($this->cipherBuffer === '' && $this->stream->eof())) {
      $options |= OPENSSL_ZERO_PADDING;
    } else {
      $cipherBufferLen = strlen($this->cipherBuffer);
      if ($cipherBufferLen < 10) {
        $this->cipherBuffer = substr($cipherText, strlen($cipherText) - (10 - $cipherBufferLen)) . $this->cipherBuffer;
        $cipherText = substr($cipherText, 0, strlen($cipherText) - (10 - $cipherBufferLen));
      }
    }

    hash_update($this->hashResource, $cipherText);

    if (strlen($this->cipherBuffer) < self::BLOCK_SIZE + 10) {
      $mac = substr($this->cipherBuffer, strlen($this->cipherBuffer) - 10, 10);
      $this->cipherBuffer = substr($this->cipherBuffer, 0, strlen($this->cipherBuffer) - 10);

      hash_update($this->hashResource, $this->cipherBuffer);

      $hash = hash_final($this->hashResource, true);

      if (!$this->isSignatureValid($hash, $mac)) {
        throw new \BadMethodCallException('Validation failed');
      }
    }

    $plainText = openssl_decrypt(
      $cipherText,
      "AES-256-CBC",
      $this->keys->getCipherKey(),
      $options,
      $this->keys->getIv()
    );

    $this->keys->setIv(substr($cipherText, strlen($cipherText) - 16));

    return $plainText;
  }

  private function initializeHash() {
    $this->hashResource = hash_init('sha256', HASH_HMAC, $this->keys->getMacKey());
    hash_update($this->hashResource, $this->keys->getIv());
  }
}

?>