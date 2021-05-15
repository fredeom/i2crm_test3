<?php

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;
use Jsq\EncryptionStreams\Cbc;
use Jsq\EncryptionStreams\AesEncryptingStream;

class WhatsAppEncryptingStream implements StreamInterface {

  const SIDECAR_BLOCK_SIZE = 64 * 1024;

  use StreamDecoratorTrait;

  private $buffer = '';

  private $sideCarBuffer = '';
  private $sideCar = '';

  private $keys;
  private $stream;

  public function __construct(StreamInterface $stream, CipherKeyGenerator $keys) {
    $this->stream = new AesEncryptingStream($stream, $keys->getCipherKey(), new Cbc($keys->getIv()));
    $this->keys = $keys;

    $this->initializeHash();
  }

  public function read($length) {
    $bufferLength = strlen($this->buffer);
    if ($length > $bufferLength) {
      $cipherText = $this->stream->read($length - $bufferLength);
      $this->buffer .= $cipherText;
      hash_update($this->hashResource, $cipherText);
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