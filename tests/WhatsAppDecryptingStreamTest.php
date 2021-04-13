<?php

declare(strict_types=1);

require_once (__DIR__ . '/../src/CipherKeyGenerator.php');
require_once (__DIR__ . '/../src/WhatsAppDecryptingStream.php');

use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7;
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

?>