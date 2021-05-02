<?php

use Psr\Http\Message\StreamInterface;

require_once(__DIR__ . '/CipherKeyGenerator.php');

class WhatsAppEncryptingStream implements StreamInterface {

  const BLOCK_SIZE = 32;
  const SIDECAR_BLOCK_SIZE = 64 * 1024;

  private $buffer = '';
  private $sideCarBuffer = '';
  private $sideCar = '';
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
    $this->sideCarBuffer = '';
    $this->sideCar = '';
    $this->stream->close();
  }

  public function detach() {
    $this->buffer = '';
    $this->sideCarBuffer = '';
    $this->sideCar = '';
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
    return $this->stream->eof() && $this->buffer == '';
  }

  public function read($length) {
    if ($length > strlen($this->buffer)) {
      $this->buffer .= $this->encryptBlock(
          self::BLOCK_SIZE * ceil(($length - strlen($this->buffer)) / self::BLOCK_SIZE)
      );
      if ($this->stream->eof()) {
        $hash = hash_final($this->hashResource, true);
        $this->buffer .= substr($hash, 0, 10);
      }
    }
    $data = substr($this->buffer, 0, $length);

    $this->sideCarBuffer .= $data;
    $this->updateSideCar(false);

    $this->buffer = substr($this->buffer, $length);
    return $data ? $data : '';
  }

  private function encryptBlock($length) {
    if ($this->stream->eof()) {
      return '';
    }

    $plainText = '';
    do {
        $plainText .= $this->stream->read($length - strlen($plainText));
    } while (strlen($plainText) < $length && !$this->stream->eof());

    $options = OPENSSL_RAW_DATA;
    if (!$this->stream->eof()) {
        $options |= OPENSSL_ZERO_PADDING;
    }

    $cipherText = openssl_encrypt(
      $plainText,
      "AES-256-CBC",
      $this->keys->getCipherKey(),
      $options,
      $this->keys->getIv()
    );

    hash_update($this->hashResource, $cipherText);

    $this->keys->setIv(substr($cipherText, strlen($cipherText) - 16));

    return $cipherText;
  }

  private function signWithMacKey($text) {
    return substr(hash_hmac("sha256", $text, $this->keys->getMacKey(), true), 0, 10);
  }

  private function updateSideCar($isFinal = false) {
    if (in_array($this->keys->getMediaType(), ["VIDEO", "AUDIO"])) {
      while (strlen($this->sideCarBuffer) >= self::SIDECAR_BLOCK_SIZE) {
        $chunk = substr($this->sideCarBuffer, 0, self::SIDECAR_BLOCK_SIZE + 16);
        $this->sideCar .= $this->signWithMacKey($chunk);
        $this->sideCarBuffer = substr($this->sideCarBuffer, self::SIDECAR_BLOCK_SIZE);
      }
      if ($isFinal && $this->sideCarBuffer != '') {
        $this->sideCar .= $this->signWithMacKey($this->sideCarBuffer);
        $this->sideCarBuffer = '';
      }
    }
  }

  public function getSidecar() {
    $this->updateSideCar(true);
    return $this->sideCar;
  }

  private function initializeHash() {
    $this->hashResource = hash_init('sha256', HASH_HMAC, $this->keys->getMacKey());
    hash_update($this->hashResource, $this->keys->getIv());
    $this->sideCarBuffer = $this->keys->getIv();
  }
} 
 
?>