<?php

require_once (__DIR__ . '/TypeSpecificApplicationInfo.php');

class CipherKeyGenerator {
  private $mediaKey;
  private $mediaKeyExpanded;
  private $iv;
  private $cipherKey;
  private $macKey;
  private $refKey;
  private $mediaType;

  public function __construct($key, $mediaType) {
    $this->mediaType = $mediaType;
    $this->typeSpecificAppInfo = TypeSpecificApplicationInfo::getFromString($this->mediaType);
    $this->mediaKey = $key;
    $this->mediaKeyExpanded = hash_hkdf("sha256", $this->mediaKey, 112, $this->typeSpecificAppInfo);
    $this->iv = substr($this->mediaKeyExpanded, 0, 16);
    $this->cipherKey = substr($this->mediaKeyExpanded, 16, 48 - 16);
    $this->macKey = substr($this->mediaKeyExpanded, 48, 80 - 48);
    $this->refKey = substr($this->mediaKeyExpanded, 80, 112 - 80);
  }

  public function getTypeSpecificAppInfo() {
    return $this->typeSpecificAppInfo;
  }

  public function getMediaType() {
    return $this->mediaType;
  }

  public function getMediaKey() {
    return $this->mediaKey;
  }

  public function getMediaKeyExpanded() {
    return $this->mediaKeyExpanded;
  }

  public function getIv() {
    return $this->iv;
  }

  public function setIv($iv) {
    $this->iv = $iv;
  }

  public function getCipherKey() {
    return $this->cipherKey;
  }

  public function getMacKey() {
    return $this->macKey;
  }

  public function getRefKey() {
    return $this->refKey;
  }
}

?>