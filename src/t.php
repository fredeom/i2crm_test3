<?php

require 'vendor/autoload.php';
//require_once (__DIR__ . '/../vendor/autoload.php');

require_once ('src/CipherKeyGenerator.php');
require_once ('src/WhatsAppEncryptingStream.php');

use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Utils;

$mediaKey = file_get_contents('samples/IMAGE.key');
$keys = new CipherKeyGenerator($mediaKey, "IMAGE");
$inStream = Utils::streamFor(Utils::tryFopen('samples/IMAGE.original', 'r'));
$cipherTextStream = new WhatsAppEncryptingStream($inStream, $keys);

//echo $cipherTextStream->read(100);

$cipherText = openssl_encrypt(
  "01234567890123456789012345678901",
  "AES-256-CBC",
  $keys->getCipherKey(),
  OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
  $keys->getIv()
);

echo $cipherText . "\n";

?>