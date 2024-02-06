<?php

	function check_proof($ton_proof, $account) 
    {
        $account["address"] = str_replace("0:", "", $account["address"]);

        $workchain = 0; // 0 - рабочая сеть
        $address = hex2bin($account["address"]);
        $public_key = hex2bin($account["publicKey"]);
        
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
        $signature_message = "\xFF\xFF" . utf8_encode("ton-connect") . $hashed_message;
        $hashed_signature_message = hash("sha256", $signature_message, true);

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