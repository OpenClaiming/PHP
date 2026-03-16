<?php

class OpenClaim {

	public static function canonicalize($claim) {
		unset($claim["sig"]);
		ksort($claim);
		return json_encode($claim, JSON_UNESCAPED_SLASHES);
	}

	public static function sign($claim, $privateKey) {
		$canon = self::canonicalize($claim);
		$hash = hash("sha256",$canon,true);
		openssl_sign($hash,$signature,$privateKey,OPENSSL_ALGO_SHA256);
		$claim["sig"] = base64_encode($signature);
		return $claim;
	}

	public static function verify($claim,$publicKey) {
		if(!isset($claim["sig"])) return false;
		$sig = base64_decode($claim["sig"]);
		$canon = self::canonicalize($claim);
		$hash = hash("sha256",$canon,true);
		return openssl_verify($hash,$sig,$publicKey,OPENSSL_ALGO_SHA256) === 1;
	}

}
?>