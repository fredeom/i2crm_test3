<?php

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use GuzzleHttp\Psr7\AppendStream;
use GuzzleHttp\Psr7\LimitStream;
use GuzzleHttp\Psr7\Utils;

use Psr\Http\Message\StreamInterface;
use Jsq\EncryptionStreams\Cbc;
use Jsq\EncryptionStreams\AesDecryptingStream;
use Jsq\EncryptionStreams\HashingStream;

class WhatsAppDecryptingStream implements StreamInterface {

  use StreamDecoratorTrait;

  private $composed;
  private $hash = null;

  private $buffer = '';

  private $keys;
  private $stream;

  public function __construct(StreamInterface $stream, CipherKeyGenerator $keys) {
    $this->composed = new AppendStream([Utils::streamFor($keys->getIv()), $stream]);
    $limited = new LimitStream($this->composed, $this->composed->getSize() - 10, 0);
    $hashed = new HashingStream(
      $limited,
      $keys->getMacKey(),
      function ($hash) {                       // Due to problem with AesDecryptingStream wrapping of HashingStream
        if (!$this->hash) $this->hash = $hash; // and additional call to read after stream is finalized this function
      }                                        // calls twice and spoil hash. Need remove check after fixing the same issue here and below.
    );

    $hashed->read(strlen($keys->getIv()));

    $this->stream = new AesDecryptingStream($hashed, $keys->getCipherKey(), new Cbc($keys->getIv()));
    $this->keys = $keys;
  }

  public function read($length) {
    $bufferLength = strlen($this->buffer);
    if ($length > $bufferLength) {
      error_reporting(E_ALL ^ E_WARNING);                             // AesDecryptingStream calls stream->read on HashingStream again
      $this->buffer .= $this->stream->read($length - $bufferLength);  // after reaching eof of the stream causing hash_final call twice
      error_reporting(E_ALL);                                         // and issue warning on obsolete hashResource. Need check stream eof before reading again on AesDecryptingStream:113 ((($this->cipherBuffer = !$this->stream->eof() ? $this->stream->read(self::BLOCK_SIZE) : '';)))
    }
    $data = substr($this->buffer, 0, $length);
    $this->buffer = substr($this->buffer, $length);

    if ($this->stream->eof()) {
      $mac = $this->composed->read(10);

      if ($mac != substr($this->hash, 0, 10)) {
        throw new \BadMethodCallException('Validation failed');
      }
    }
    return $data ? $data : '';
  }
}

?>