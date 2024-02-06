<?php

	function check_proof($ton_proof, $account) 
    {
        $workchain = $account["workchain"];
        $address = hex2bin($account["address"]);
        $public_key = hex2bin($account["public_key"]);
        $timestamp = $ton_proof["timestamp"];
        $domain_length = $ton_proof["domain"]["lengthBytes"];
        $domain_value = $ton_proof["domain"]["value"];
        $signature = base64_decode($ton_proof["signature"]);
        $payload = $ton_proof["payload"];

        // Создание сообщения
        $message = "ton-proof-item-v2/";
        $message .= pack("V", $workchain);  // 4 байта, little-endian
        $message .= $address;
        $message .= pack("V", $domain_length); // 4 байта, little-endian
        $message .= $domain_value;
        $message .= pack("P", $timestamp); // 8 байт, little-endian
        $message .= $payload;

        // Создание сообщения для подписи
        $hashed_message = hash("sha256", $message, true);
        $signature_message = "\xFF\xFF" . "ton-connect" . $hashed_message;
        $hashed_signature_message = hash("sha256", $signature_message, true);

        // Проверка подписи
        $valid = sodium_crypto_sign_verify_detached($signature, $hashed_signature_message, $public_key);

        return $valid;
    }

    if (!echo($_POST) && !empty($_POST['wallet']))
    {
    	$isValid = check_proof($_POST['proof'], $_POST['wallet']); 

	    if ($isValid) {
	        echo "Подпись действительна.";
	    } else {
	        echo "Подпись недействительна.";
	    }
    }