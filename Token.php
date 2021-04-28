<?php
function stop(){
  header("HTTP/1.1 401 Unauthorized");
}
class Token {

	public $item;
	public $user;

	function __construct() {

		$item = null;
		if (isset($_SERVER['Authorization'])) {
			$item = trim($_SERVER["Authorization"]);
		} else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
			$item = trim($_SERVER["HTTP_AUTHORIZATION"]);
		} elseif (function_exists('apache_request_headers')) {
			$requestHeaders = apache_request_headers();
			$requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders	));
			if (isset($requestHeaders['Authorization'])) $item = trim($requestHeaders['Authorization']);
		}
		if (!empty($item)) {
			if (preg_match('/Bearer\s(\S+)/', $item, $matches)){
				if($this->validate($matches[1]) == 0) stop();
				$this->item = $matches[1];
			}
		} else stop();

	}

	function getToken(){
		return $this->item;
	}

	function newToken($headers, $payload) {

		$secret = $this->getKey();

		$headers_encoded = base64url_encode(json_encode($headers));

		$payload_encoded = base64url_encode(json_encode($payload));

		$signature = hash_hmac('SHA256', "$headers_encoded.$payload_encoded", $secret->Key, true);
		$signature_encoded = base64url_encode($signature);

		$jwt = "$headers_encoded.$payload_encoded.$signature_encoded";

		return $jwt;
	}

	function validate($jwt) {

		$secret = $this->getKey();

		// split the jwt
		$tokenParts = explode('.', $jwt);
		$header = base64_decode($tokenParts[0]);
		$payload = base64_decode($tokenParts[1]);
		$signature_provided = $tokenParts[2];

		// save user id
		$item = json_decode($payload);
		$this->user = $item->Id;

		// check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
		if(((int)$item->exp - time()) < 0) head(5);

		// build a signature based on the header and payload using the secret
		$base64_url_header = $this->base64url_encode($header);
		$base64_url_payload = $this->base64url_encode($payload);
		$signature = hash_hmac('SHA256', $base64_url_header . "." . $base64_url_payload, $secret->Key, true);
		$base64_url_signature = $this->base64url_encode($signature);

		// verify it matches the signature provided in the jwt
		$is_signature_valid = ($base64_url_signature === $signature_provided);

		return $is_token_expired || !$is_signature_valid ? FALSE : TRUE;

	}

	function base64url_encode($str) {
		return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
	}

	function getKey(){
		return json_decode(file_get_contents("secret.json"));
	}

	function addToken($item){
		$this->item = $item;
	}

}
