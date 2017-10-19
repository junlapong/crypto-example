<?php

include 'AES.php';

$inputText = "My text to encrypt";
$inputKey  = "My text to encrypt";
$blockSize = 256;

$aes = new AES($inputText, $inputKey, $blockSize);
$enc = $aes->encrypt();

$aes->setData($enc);
$dec=$aes->decrypt();

echo "message      : " . $inputText . PHP_EOL;
echo "encrypted msg: " . $enc . PHP_EOL;
echo "decrypted msg: " . $dec . PHP_EOL;

// EOL