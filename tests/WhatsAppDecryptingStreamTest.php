<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\Utils;

final class WhatsAppDecryptingStreamTest extends TestCase {
  private const sampleDir = __DIR__ . '/../samples/';

  public function testImageDecryption() {
    $this->testFileDecryption("IMAGE");
  }

  public function testAudioDecryption() {
    $this->testFileDecryption("AUDIO");
  }

  public function testVideoDecryption() {
    $this->testFileDecryption("VIDEO");
  }

  public function testBugFixWithInfiniteLoopDuringDecryption() {
    $mediaType = "IMAGE";
    $mediaKey = file_get_contents(self::sampleDir . $mediaType .'.key');
    $keys = new CipherKeyGenerator($mediaKey, $mediaType);

    $inStream = Utils::streamFor(Utils::tryFopen(self::sampleDir . $mediaType . '.encrypted', 'r'));
    $decodedTextStream = new WhatsAppDecryptingStream($inStream, $keys);
    while (!$decodedTextStream->eof()) { // fix bug with eternal loop
      $decodedTextStream->read(8192);
    }
    $this->assertTrue(true);
  }

  private function testFileDecryption($mediaType) {
    $mediaKey = file_get_contents(self::sampleDir . $mediaType .'.key');
    $keys = new CipherKeyGenerator($mediaKey, $mediaType);

    $inStream = Utils::streamFor(Utils::tryFopen(self::sampleDir . $mediaType . '.encrypted', 'r'));
    $decodedTextStream = new WhatsAppDecryptingStream($inStream, $keys);

    $tmpFile = tmpfile();
    $metadata = stream_get_meta_data($tmpFile);
    $tmpUri = $metadata['uri'];

    $decodedTextFile = Utils::streamFor(Utils::tryFopen($tmpUri, 'w'));
    Utils::copyToStream($decodedTextStream, $decodedTextFile);

    $this->assertTrue(md5_file($tmpUri) == md5_file(self::sampleDir . $mediaType . '.original'));
  }
}
