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
				$this->validate($matches[1]);
				$this->token = $matches[1];
			}
		} else stop();

	}

	function getToken(){
		return $this->item;
	}

	function newToken($payload, $signature = null) {

		$secret = $this->getKey();

		$headers_encoded = base64_encode(json_encode(["alg" => "HS256", "typ" => "JWT"]));

		if(is_object($payload) || is_array($payload)) $payload = json_encode($payload);
		$payload_encoded = base64_encode($payload);

		$signature_encoded = base64_encode(hash_hmac('SHA256', $headers_encoded .".". $payload_encoded, $secret->Key, true));

		if($signature && (string)$signature != (string)$signature_encoded) head(4, [
			"status" => 400,
			"fi" => "Tokenin allekirjoitus ei vastaa alkuperäistä.",
			"en" => "Token signature is invalid."
		]);

		$this->token = $headers_encoded .".". $payload_encoded .".". $signature_encoded;

		return $this->token;
	}

	function validate($jwt) {

		$secret = $this->getKey();
		$tokenParts = explode('.', $jwt);
		$header = base64_decode($tokenParts[0]);
		$payload = base64_decode($tokenParts[1]);
		$signature_provided = $tokenParts[2];

		$item = json_decode($payload);
		$this->userId = $item->id;

		// check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
		$time = (int)$item->exp - time();
		if($time < 0) head(5, [
			"status" => 401,
			"fi" => "Token ei ole voimassa.",
			"en" => "Token is not valid."]
		);

		// build a signature based on the header and payload using the secret
		$readyToken = $this->newToken($payload, $signature_provided);

		return TRUE;

	}

	function getKey(){
		return json_decode(file_get_contents("secret.json"));
	}

	function addToken($item){
		$this->item = $item;
	}

}
