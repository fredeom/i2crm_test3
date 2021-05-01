<?php

declare(strict_types=1);

require_once (__DIR__ . '/../src/CipherKeyGenerator.php');
require_once (__DIR__ . '/../src/WhatsAppEncryptingStream.php');

use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Utils;

final class WhatsAppEncryptingStreamTest extends TestCase {
  private const sampleDir = __DIR__ . '/../samples/';

  public function testImageEncryption() {
    $this->testFileEncryption("IMAGE");
  }

  public function testAudioEncryption() {
    $this->testFileEncryption("AUDIO");
  }

  public function testBaseVideoEncryption() {
    $this->testFileEncryption("VIDEO", false);
  }

  public function testVideoEncryptionSideCar() {
    $this->testFileEncryption("VIDEO", true);
  }


  private function testFileEncryption($mediaType, $testSideCar = false) {
    $mediaKey = file_get_contents(self::sampleDir . $mediaType . '.key');
    $keys = new CipherKeyGenerator($mediaKey, $mediaType);

    $inStream = Utils::streamFor(Utils::tryFopen(self::sampleDir . $mediaType .'.original', 'r'));
    $cipherTextStream = new WhatsAppEncryptingStream($inStream, $keys);

    $tmpFile = tmpfile();
    $metadata = stream_get_meta_data($tmpFile);
    $tmpUri = $metadata['uri'];

    $cipherTextFile = Utils::streamFor(Utils::tryFopen($tmpUri, 'w'));
    Utils::copyToStream($cipherTextStream, $cipherTextFile);

    if (!$testSideCar) {
      $this->assertTrue(md5_file($tmpUri) == md5_file(self::sampleDir . $mediaType . '.encrypted'));
    }

    if ($testSideCar && in_array($mediaType, ["VIDEO"])) {
      $tmpFile = tmpfile();
      $metadata = stream_get_meta_data($tmpFile);
      $tmpUriSideCar = $metadata['uri'];

      file_put_contents($tmpUriSideCar, $cipherTextStream->getSidecar());

      $this->assertTrue(md5_file($tmpUriSideCar) == md5_file(self::sampleDir . $mediaType . '.sidecar'));
    }
  }
}

?>