<?php

class OpenClaim_EVM
{
	const PAYMENT_DOMAIN_NAME = "OpenClaiming.payments";
	const AUTHORIZATION_DOMAIN_NAME = "OpenClaiming.authorizations";
	const VERSION = "1";

	private static $PAYMENT_TYPEHASH = null;
	private static $AUTHORIZATION_TYPEHASH = null;
	private static $AUTHORIZATION_CONSTRAINT_TYPEHASH = null;
	private static $AUTHORIZATION_CONTEXT_TYPEHASH = null;

	private static function initTypehashes()
	{
		if (self::$PAYMENT_TYPEHASH !== null) {
			return;
		}

		self::$PAYMENT_TYPEHASH = self::keccakUtf8(
			"Payment(address payer,address token,bytes32 recipientsHash,uint256 max,uint256 line,uint256 nbf,uint256 exp)"
		);

		self::$AUTHORIZATION_TYPEHASH = self::keccakUtf8(
			"Authorization(address authority,address subject,bytes32 actorsHash,bytes32 rolesHash,bytes32 actionsHash,bytes32 constraintsHash,bytes32 contextsHash,uint256 nbf,uint256 exp)"
		);

		self::$AUTHORIZATION_CONSTRAINT_TYPEHASH = self::keccakUtf8(
			"Constraint(string key,string op,string value)"
		);

		self::$AUTHORIZATION_CONTEXT_TYPEHASH = self::keccakUtf8(
			"Context(string type,string value)"
		);
	}

	private static function requireArray($value, $name)
	{
		if (!is_array($value)) {
			throw new Exception($name . " must be an array");
		}
	}

	private static function requireClaimArray($claim)
	{
		if (!is_array($claim)) {
			throw new Exception("claim must be an array");
		}
	}

	private static function requireField($claim, $field)
	{
		$value = self::readField($claim, $field, null);
		if ($value === null || $value === "") {
			throw new Exception("claim." . $field . " is required for EIP712");
		}
		return $value;
	}

	private static function requireAddress($value, $name)
	{
		if (!is_string($value) || !preg_match('/^0x[a-fA-F0-9]{40}$/', $value)) {
			throw new Exception($name . " must be a valid address");
		}
	}

	private static function requireChainId($value)
	{
		if ($value === null || $value === "") {
			throw new Exception("claim.chainId is required for EIP712");
		}
	}

	private static function toArray($value)
	{
		if ($value === null) {
			return array();
		}
		return is_array($value) ? $value : array($value);
	}

	private static function lower($value)
	{
		return strtolower((string)$value);
	}

	private static function strip0x($hex)
	{
		return strpos($hex, "0x") === 0 || strpos($hex, "0X") === 0
			? substr($hex, 2)
			: $hex;
	}

	private static function hex($value)
	{
		$hex = self::strip0x((string)$value);
		return "0x" . strtolower($hex);
	}

	private static function readField($claim, $key, $fallback = null)
	{
		if (is_array($claim) && array_key_exists($key, $claim) && $claim[$key] !== null) {
			return $claim[$key];
		}
		if (
			is_array($claim)
			&& isset($claim["stm"])
			&& is_array($claim["stm"])
			&& array_key_exists($key, $claim["stm"])
			&& $claim["stm"][$key] !== null
		) {
			return $claim["stm"][$key];
		}
		return $fallback;
	}

	private static function readUint($claim, $key, $fallback = "0")
	{
		$value = self::readField($claim, $key, null);
		if ($value === null || $value === "") {
			return (string)$fallback;
		}
		return (string)$value;
	}

	private static function keccakUtf8($value)
	{
		if (class_exists("\\kornrunner\\Keccak")) {
			return "0x" . \kornrunner\Keccak::hash((string)$value, 256);
		}

		throw new Exception(
			"Keccak implementation not found. Install kornrunner/keccak or replace keccakUtf8()."
		);
	}

	private static function keccakHexData($hexData)
	{
		$bin = hex2bin(self::strip0x($hexData));
		if ($bin === false) {
			throw new Exception("Invalid hex data");
		}

		if (class_exists("\\kornrunner\\Keccak")) {
			return "0x" . \kornrunner\Keccak::hash($bin, 256);
		}

		throw new Exception(
			"Keccak implementation not found. Install kornrunner/keccak or replace keccakHexData()."
		);
	}

	private static function padHex($hex, $bytes)
	{
		$hex = self::strip0x($hex);
		return str_pad(strtolower($hex), $bytes * 2, "0", STR_PAD_LEFT);
	}

	private static function encodeUint256($value)
	{
		if (is_int($value)) {
			$value = (string)$value;
		}
		if (!is_string($value)) {
			$value = (string)$value;
		}

		if (strpos($value, "0x") === 0 || strpos($value, "0X") === 0) {
			return self::padHex($value, 32);
		}

		if (extension_loaded("gmp")) {
			$hex = gmp_strval(gmp_init($value, 10), 16);
			return self::padHex($hex, 32);
		}

		if (function_exists("bccomp")) {
			$n = $value;
			$hex = "";
			while (bccomp($n, "0") > 0) {
				$rem = bcmod($n, "16");
				$hex = dechex((int)$rem) . $hex;
				$n = bcdiv($n, "16", 0);
			}
			if ($hex === "") {
				$hex = "0";
			}
			return self::padHex($hex, 32);
		}

		if (preg_match('/^\d+$/', $value)) {
			$hex = dechex((int)$value);
			return self::padHex($hex, 32);
		}

		throw new Exception("Cannot encode uint256 without GMP or BCMath for large values");
	}

	private static function encodeAddress($address)
	{
		self::requireAddress($address, "address");
		return self::padHex(self::strip0x($address), 32);
	}

	private static function encodeBytes32($value)
	{
		$hex = self::strip0x($value);
		if (strlen($hex) !== 64) {
			throw new Exception("bytes32 value must be 32 bytes");
		}
		return strtolower($hex);
	}

	private static function encodeDynamicArrayHead($offsetWords)
	{
		return self::encodeUint256($offsetWords * 32);
	}

	private static function abiEncodeAddressArray($values)
	{
		$values = self::toArray($values);

		$head = self::encodeUint256(32);
		$tail = self::encodeUint256(count($values));

		foreach ($values as $value) {
			self::requireAddress($value, "address array item");
			$tail .= self::encodeAddress($value);
		}

		return "0x" . $head . $tail;
	}

	private static function abiEncodeBytes32Array($values)
	{
		$values = self::toArray($values);

		$head = self::encodeUint256(32);
		$tail = self::encodeUint256(count($values));

		foreach ($values as $value) {
			$tail .= self::encodeBytes32($value);
		}

		return "0x" . $head . $tail;
	}

	private static function abiEncodeStatic($types, $values)
	{
		if (count($types) !== count($values)) {
			throw new Exception("ABI types and values length mismatch");
		}

		$out = "";

		foreach ($types as $i => $type) {
			$value = $values[$i];

			switch ($type) {
				case "bytes32":
					$out .= self::encodeBytes32($value);
					break;

				case "address":
					$out .= self::encodeAddress($value);
					break;

				case "uint256":
					$out .= self::encodeUint256($value);
					break;

				default:
					throw new Exception("Unsupported static ABI type: " . $type);
			}
		}

		return "0x" . $out;
	}

	public static function hashRecipients($recipients)
	{
		return self::keccakHexData(self::abiEncodeAddressArray($recipients));
	}

	public static function hashActors($actors)
	{
		return self::keccakHexData(self::abiEncodeAddressArray($actors));
	}

	public static function hashStringArray($values)
	{
		$values = self::toArray($values);
		$hashes = array();

		foreach ($values as $value) {
			$hashes[] = self::keccakUtf8((string)$value);
		}

		return self::keccakHexData(self::abiEncodeBytes32Array($hashes));
	}

	public static function hashConstraint($constraint)
	{
		self::initTypehashes();
		self::requireArray($constraint, "constraint");

		$encoded = self::abiEncodeStatic(
			array("bytes32", "bytes32", "bytes32", "bytes32"),
			array(
				self::$AUTHORIZATION_CONSTRAINT_TYPEHASH,
				self::keccakUtf8($constraint["key"] ?? ""),
				self::keccakUtf8($constraint["op"] ?? ""),
				self::keccakUtf8($constraint["value"] ?? "")
			)
		);

		return self::keccakHexData($encoded);
	}

	public static function hashConstraints($constraints)
	{
		$constraints = self::toArray($constraints);
		$hashes = array();

		foreach ($constraints as $constraint) {
			$hashes[] = self::hashConstraint($constraint);
		}

		return self::keccakHexData(self::abiEncodeBytes32Array($hashes));
	}

	public static function hashContext($context)
	{
		self::initTypehashes();
		self::requireArray($context, "context");

		$encoded = self::abiEncodeStatic(
			array("bytes32", "bytes32", "bytes32"),
			array(
				self::$AUTHORIZATION_CONTEXT_TYPEHASH,
				self::keccakUtf8($context["typ"] ?? ""),
				self::keccakUtf8($context["value"] ?? "")
			)
		);

		return self::keccakHexData($encoded);
	}

	public static function hashContexts($contexts)
	{
		$contexts = self::toArray($contexts);
		$hashes = array();

		foreach ($contexts as $context) {
			$hashes[] = self::hashContext($context);
		}

		return self::keccakHexData(self::abiEncodeBytes32Array($hashes));
	}

	public static function detectType($claim)
	{
		$payer = self::readField($claim, "payer", null);
		$token = self::readField($claim, "token", null);
		$line = self::readField($claim, "line", null);

		if ($payer && $token !== null && $line !== null) {
			return "payment";
		}

		$authority = self::readField($claim, "authority", null);
		$subject = self::readField($claim, "subject", null);

		if ($authority && $subject) {
			return "authorization";
		}

		return null;
	}

	public static function toPaymentPayload($claim)
	{
		self::requireClaimArray($claim);
		self::initTypehashes();

		$chainId = $claim["chainId"] ?? null;
		$contract = $claim["contract"] ?? null;
		$payer = self::requireField($claim, "payer");
		$token = self::requireField($claim, "token");
		$recipients = self::toArray(self::readField($claim, "recipients", array()));

		self::requireChainId($chainId);
		self::requireAddress($contract, "claim.contract");
		self::requireAddress($payer, "claim.payer");
		self::requireAddress($token, "claim.token");

		return array(
			"primaryType" => "Payment",
			"domain" => array(
				"name" => self::PAYMENT_DOMAIN_NAME,
				"version" => self::VERSION,
				"chainId" => $chainId,
				"verifyingContract" => $contract
			),
			"types" => array(
				"Payment" => array(
					array("name" => "payer", "type" => "address"),
					array("name" => "token", "type" => "address"),
					array("name" => "recipientsHash", "type" => "bytes32"),
					array("name" => "max", "type" => "uint256"),
					array("name" => "line", "type" => "uint256"),
					array("name" => "nbf", "type" => "uint256"),
					array("name" => "exp", "type" => "uint256")
				)
			),
			"value" => array(
				"payer" => $payer,
				"token" => $token,
				"recipientsHash" => self::hashRecipients($recipients),
				"max" => self::readUint($claim, "max", "0"),
				"line" => self::readUint($claim, "line", "0"),
				"nbf" => self::readUint($claim, "nbf", "0"),
				"exp" => self::readUint($claim, "exp", "0")
			),
			"data" => array(
				"recipients" => $recipients
			)
		);
	}

	public static function toAuthorizationPayload($claim)
	{
		self::requireClaimArray($claim);
		self::initTypehashes();

		$chainId = $claim["chainId"] ?? null;
		$contract = $claim["contract"] ?? null;
		$authority = self::requireField($claim, "authority");
		$subject = self::requireField($claim, "subject");
		$actors = self::toArray(self::readField($claim, "actors", array()));
		$roles = self::toArray(self::readField($claim, "roles", array()));
		$actions = self::toArray(self::readField($claim, "actions", array()));
		$constraints = self::toArray(self::readField($claim, "constraints", array()));
		$contexts = self::toArray(self::readField($claim, "contexts", array()));

		self::requireChainId($chainId);
		self::requireAddress($contract, "claim.contract");
		self::requireAddress($authority, "claim.authority");
		self::requireAddress($subject, "claim.subject");

		return array(
			"primaryType" => "Authorization",
			"domain" => array(
				"name" => self::AUTHORIZATION_DOMAIN_NAME,
				"version" => self::VERSION,
				"chainId" => $chainId,
				"verifyingContract" => $contract
			),
			"types" => array(
				"Authorization" => array(
					array("name" => "authority", "type" => "address"),
					array("name" => "subject", "type" => "address"),
					array("name" => "actorsHash", "type" => "bytes32"),
					array("name" => "rolesHash", "type" => "bytes32"),
					array("name" => "actionsHash", "type" => "bytes32"),
					array("name" => "constraintsHash", "type" => "bytes32"),
					array("name" => "contextsHash", "type" => "bytes32"),
					array("name" => "nbf", "type" => "uint256"),
					array("name" => "exp", "type" => "uint256")
				)
			),
			"value" => array(
				"authority" => $authority,
				"subject" => $subject,
				"actorsHash" => self::hashActors($actors),
				"rolesHash" => self::hashStringArray($roles),
				"actionsHash" => self::hashStringArray($actions),
				"constraintsHash" => self::hashConstraints($constraints),
				"contextsHash" => self::hashContexts($contexts),
				"nbf" => self::readUint($claim, "nbf", "0"),
				"exp" => self::readUint($claim, "exp", "0")
			),
			"data" => array(
				"actors" => $actors,
				"roles" => $roles,
				"actions" => $actions,
				"constraints" => $constraints,
				"contexts" => $contexts
			)
		);
	}

	public static function toPayload($claim)
	{
		$type = self::detectType($claim);

		if ($type === "payment") {
			return self::toPaymentPayload($claim);
		}
		if ($type === "authorization") {
			return self::toAuthorizationPayload($claim);
		}

		throw new Exception("Unable to detect EIP712 claim type");
	}

	public static function sign($claim, callable $signTypedData)
	{
		$payload = self::toPayload($claim);
		return $signTypedData(
			$payload["domain"],
			$payload["types"],
			$payload["value"]
		);
	}

	public static function verify($claim, $signature, $expectedAddress, callable $recoverTypedData)
	{
		$payload = self::toPayload($claim);

		$recovered = $recoverTypedData(
			$payload["domain"],
			$payload["types"],
			$payload["value"],
			$signature
		);

		return self::lower($recovered) === self::lower($expectedAddress);
	}

	public static function verifyKey($claim, $keyObj, $signature, callable $recoverTypedData)
	{
		if (!is_array($keyObj) || (($keyObj["typ"] ?? null) !== "EIP712")) {
			return false;
		}

		return self::verify(
			$claim,
			$signature,
			$keyObj["value"],
			$recoverTypedData
		);
	}
}