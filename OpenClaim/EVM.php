<?php

use OpenClaim\EVM;

class OpenClaim
{
	// ---------- HELPERS ----------

	private static function toArray($v) {
		if ($v === null) return [];
		return is_array($v) ? $v : [$v];
	}

	private static function normalizeSignatures($arr) {
		$arr = self::toArray($arr);
		$out = [];
		foreach ($arr as $v) {
			$out[] = $v === null ? null : (string)$v;
		}
		return $out;
	}

	private static function ensureSortedKeys($keys) {
		$sorted = $keys;
		sort($sorted, SORT_STRING);
		if ($sorted !== $keys) {
			throw new Exception("keys must be lexicographically sorted");
		}
	}

	private static function ensureUniqueKeys($keys) {
		if (count($keys) !== count(array_unique($keys))) {
			throw new Exception("duplicate keys not allowed");
		}
	}

	private static function buildSortedKeyState($keysInput, $sigsInput) {

		$keys = self::toArray($keysInput);
		$sigs = self::normalizeSignatures($sigsInput);

		self::ensureUniqueKeys($keys);

		if (count($sigs) > count($keys)) {
			throw new Exception("too many signatures");
		}

		$pairs = [];

		foreach ($keys as $i => $k) {
			$pairs[] = [
				"key" => $k,
				"sig" => $i < count($sigs) ? $sigs[$i] : null
			];
		}

		usort($pairs, function ($a, $b) {
			return strcmp($a["key"], $b["key"]);
		});

		$keys = [];
		$sigs = [];

		foreach ($pairs as $p) {
			$keys[] = $p["key"];
			$sigs[] = $p["sig"];
		}

		self::ensureSortedKeys($keys);

		return ["keys" => $keys, "signatures" => $sigs];
	}

	private static function parseVerifyPolicy($policy, $totalKeys) {

		if ($policy === null) return ["minValid" => 1];

		if (is_int($policy)) return ["minValid" => $policy];

		if (isset($policy["mode"]) && $policy["mode"] === "all") {
			return ["minValid" => $totalKeys];
		}

		if (isset($policy["minValid"]) && is_int($policy["minValid"])) {
			return ["minValid" => $policy["minValid"]];
		}

		return ["minValid" => 1];
	}

	private static function resolveKey($keyStr) {

		$parts = explode(":", $keyStr, 2);
		if (count($parts) < 2) return null;

		return [
			"typ" => strtoupper($parts[0]),
			"value" => $parts[1]
		];
	}

	// ---------- CANONICAL ----------

	private static function normalize($v) {

		if (is_array($v)) {

			if (array_keys($v) !== range(0, count($v)-1)) {
				ksort($v);
			}

			foreach ($v as $k => $val) {
				$v[$k] = self::normalize($val);
			}
		}

		return $v;
	}

	public static function canonicalize($claim) {

		$obj = $claim;
		unset($obj["sig"]);

		return json_encode(self::normalize($obj), JSON_UNESCAPED_SLASHES);
	}

	// ---------- SIGN ----------

	public static function sign($claim, $privateKey, $existing = []) {

		$keys = $existing["keys"] ?? ($claim["key"] ?? []);
		$sigs = $existing["signatures"] ?? ($claim["sig"] ?? []);

		$keys = self::toArray($keys);
		$sigs = self::normalizeSignatures($sigs);

		// ---- determine format ----

		$fmt = $claim["fmt"] ?? "es256";

		if ($fmt === "eip712") {

			$address = strtolower($claim["signer"]);
			$keyStr = "eip712:" . $address;

			if (!in_array($keyStr, $keys)) {
				$keys[] = $keyStr;
			}

			$state = self::buildSortedKeyState($keys, $sigs);
			$keys = $state["keys"];
			$sigs = $state["signatures"];

			$idx = array_search($keyStr, $keys);

			$sigs[$idx] = EVM::sign($claim, $privateKey);

			return [
				"key" => $keys,
				"sig" => $sigs
			] + $claim;
		}

		// ---- ES256 ----

		$pub = openssl_pkey_get_details(
			openssl_pkey_get_private($privateKey)
		);

		$keyStr = "es256:" . preg_replace("/\s+/", "", $pub["key"]);

		if (!in_array($keyStr, $keys)) {
			$keys[] = $keyStr;
		}

		$state = self::buildSortedKeyState($keys, $sigs);
		$keys = $state["keys"];
		$sigs = $state["signatures"];

		$tmp = $claim;
		$tmp["key"] = $keys;
		$tmp["sig"] = $sigs;

		$canon = self::canonicalize($tmp);

		openssl_sign($canon, $signature, $privateKey, OPENSSL_ALGO_SHA256);

		$idx = array_search($keyStr, $keys);
		$sigs[$idx] = base64_encode($signature);

		return [
			"key" => $keys,
			"sig" => $sigs
		] + $claim;
	}

	// ---------- VERIFY ----------

	public static function verify($claim, $policy = null) {

		$keys = self::toArray($claim["key"] ?? []);
		$sigs = self::normalizeSignatures($claim["sig"] ?? []);

		if (!$keys || !$sigs) return false;

		$state = self::buildSortedKeyState($keys, $sigs);

		$keys = $state["keys"];
		$sigs = $state["signatures"];

		$canon = null;
		$valid = 0;

		foreach ($keys as $i => $k) {

			$sig = $sigs[$i];
			if (!$sig) continue;

			$keyObj = self::resolveKey($k);
			if (!$keyObj) continue;

			// ---- EIP712 ----

			if ($keyObj["fmt"] === "EIP712") {

				try {
					if (EVM::verify($claim, $sig, $keyObj["value"])) {
						$valid++;
					}
				} catch (Exception $e) {}

				continue;
			}

			// ---- ES256 ----

			if ($keyObj["typ"] !== "ES256") continue;

			if ($canon === null) {
				$tmp = $claim;
				$tmp["key"] = $keys;
				$tmp["sig"] = $sigs;
				$canon = self::canonicalize($tmp);
			}

			$ok = openssl_verify(
				$canon,
				base64_decode($sig),
				$keyObj["value"],
				OPENSSL_ALGO_SHA256
			);

			if ($ok === 1) {
				$valid++;
			}
		}

		$policyObj = self::parseVerifyPolicy($policy, count($keys));

		return $valid >= $policyObj["minValid"];
	}
}