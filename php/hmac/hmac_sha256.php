<?php

$s = hash_hmac('sha256', 'Message', 's3cr3t', true);
echo base64_encode($s) . PHP_EOL;

// EOF