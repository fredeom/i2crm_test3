<?php

class TypeSpecificApplicationInfo {
  public static $IMAGE = "WhatsApp Image Keys";
  public static $VIDEO = "WhatsApp Video Keys";
  public static $AUDIO = "WhatsApp Audio Keys";
  public static $DOCUMENT = "WhatsApp Document Keys";

  public static function getFromString($mediaType) {
    return static::${$mediaType};
  }
}

?>