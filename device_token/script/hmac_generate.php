<?php

$device_token_input = 'sample-device-token-432';
$secret_key = 'lh8Exf/G/GmQslAStSM+8Fk0FFhHPSeJDa23875/kMY=';

$signature = hash_hmac('sha256', $device_token_input, $secret_key);
echo "Signature: $signature\n";
