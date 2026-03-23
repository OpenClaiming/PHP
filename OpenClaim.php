<?php

// Optional strict canonicalizer:
// composer require sop/json-canonicalization
//
// HTTP fetch:
// Uses file_get_contents (built-in)
//
// Base64:
// Uses base64_encode / base64_decode
//
// JSON:
// Uses json_encode / json_decode
//
// P-256 / ECDSA:
// Uses OpenSSL
//
// SHA-256:
// Uses OpenSSL internal hashing
//
// Note:
// Fallback canonicalization:
// - lexicographically sorted keys
// - arrays preserved
// - numbers converted to strings
// - no whitespace
//
// Signing model:
// signature = sign( SHA256(canonicalized_claim) )

use OpenClaim\EVM;

class OpenClaim {

	// ---------- CACHE ----------

	private static $fetchCache = [];
	private static $fetchCacheTime = [];
	private static $keyCache = [];
	private static $pubKeyCache = [];
	private static $fetchTtl = 60;

	private static function fetchCached($url) {

		$now = time();

		if (isset(self::$fetchCache[$url])) {
			if (($now - self::$fetchCacheTime[$url]) < self::$fetchTtl) {
				return self::$fetchCache[$url];
			}
		}

		$data = @file_get_contents($url);

		self::$fetchCache[$url] = $data;
		self::$fetchCacheTime[$url] = $now;

		return $data;
	}

	// ---------- CANONICALIZATION ----------

	private static function normalize($v) {

		if (is_array($v)) {

			if (array_keys($v) !== range(0, count($v)-1)) {
				ksort($v);
			}

			foreach ($v as $k => $val) {
				$v[$k] = self::normalize($val);
			}
		}

		if (is_numeric($v)) {
			return (string)$v;
		}

		return $v;
	}

	private static function fallbackCanonicalize($claim) {

		unset($claim["sig"]);

		$sorted = self::normalize($claim);

		return json_encode($sorted, JSON_UNESCAPED_SLASHES);
	}

	public static function canonicalize($claim) {

		$obj = $claim;
		unset($obj["sig"]);

		if (class_exists("\\Sop\\JsonCanonicalization\\Canonicalizer")) {
			try {
				$canon = new \Sop\JsonCanonicalization\Canonicalizer();
				return $canon->canonicalize($obj);
			} catch (\Exception $e) {}
		}

		return self::fallbackCanonicalize($claim);
	}

	// ---------- HELPERS ----------

	private static function toArray($v) {
		if ($v === null) return [];
		return is_array($v) ? $v : [$v];
	}

	private static function ensureSorted($keys) {
		$sorted = $keys;
		sort($sorted, SORT_STRING);
		if ($sorted !== $keys) {
			throw new Exception("OpenClaim: key array must be lexicographically sorted");
		}
	}

	private static function ensureUnique($keys) {
		if (count(array_unique($keys)) !== count($keys)) {
			throw new Exception("OpenClaim: duplicate keys are not allowed");
		}
	}

	private static function stripPem($pem) {
		return preg_replace('/-----.*PUBLIC KEY-----|\s+/', '', $pem);
	}

	private static function derToPem($b64) {
		return "-----BEGIN PUBLIC KEY-----\n" .
			chunk_split($b64, 64, "\n") .
			"-----END PUBLIC KEY-----";
	}

	private static function getCachedPublicKey($b64) {

		if (isset(self::$pubKeyCache[$b64])) {
			return self::$pubKeyCache[$b64];
		}

		$pem = self::derToPem($b64);

		self::$pubKeyCache[$b64] = $pem;

		return $pem;
	}

	// ---------- DATA KEY ----------

	private static function parseDataKey($keyStr) {

		if (strpos($keyStr, "data:key/") !== 0) return null;

		$idx = strpos($keyStr, ",");
		if ($idx === false) return null;

		$meta = substr($keyStr, 5, $idx - 5);
		$data = substr($keyStr, $idx + 1);

		$parts = explode(";", $meta);
		$fmt = strtoupper(str_replace("key/", "", $parts[0]));

		$encoding = "raw";

		foreach ($parts as $p) {
			if ($p === "base64") $encoding = "base64";
			if ($p === "base64url") $encoding = "base64url";
		}

		if ($encoding === "base64") {
			$data = base64_decode($data);
		}

		if ($encoding === "base64url") {
			$data = strtr($data, "-_", "+/");
			$data = base64_decode($data);
		}

		return ["fmt"=>$fmt, "value"=>$data];
	}

	// ---------- KEY RESOLUTION ----------

	private static function resolveKey($keyStr, $seen = []) {

		if (in_array($keyStr, $seen)) {
			throw new Exception("OpenClaim: cyclic key reference detected");
		}

		if (isset(self::$keyCache[$keyStr])) {
			return self::$keyCache[$keyStr];
		}

		$seen[] = $keyStr;

		// data:key
		if (strpos($keyStr, "data:key/") === 0) {
			$parsed = self::parseDataKey($keyStr);
			self::$keyCache[$keyStr] = $parsed;
			return $parsed;
		}

		// URL
		if (strpos($keyStr, "http") === 0) {

			$parts = explode("#", $keyStr);
			$url = $parts[0];

			$raw = self::fetchCached($url);
			if (!$raw) return null;

			$data = json_decode($raw, true);

			$current = $data;

			foreach (array_slice($parts,1) as $p) {
				if (!$p) continue;
				$current = $current[$p] ?? null;
				if ($current === null) return null;
			}

			if (is_array($current)) {
				self::$keyCache[$keyStr] = $current;
				return $current;
			}

			if (is_string($current)) {
				$res = self::resolveKey($current, $seen);
				self::$keyCache[$keyStr] = $res;
				return $res;
			}

			return null;
		}

		// legacy
		$parts = explode(":", $keyStr, 2);
		if (count($parts) < 2) return null;

		$res = ["fmt"=>strtoupper($parts[0]), "value"=>$parts[1]];

		self::$keyCache[$keyStr] = $res;
		return $res;
	}

	// ---------- SIGN ----------

	public static function signWithExisting($claim, $privateKey, $existing = []) {

		$keys = self::toArray($existing["keys"] ?? ($claim["key"] ?? []));
		$sigs = self::toArray($existing["signatures"] ?? ($claim["sig"] ?? []));

		// EIP712 unchanged
		if (isset($claim["fmt"])) {
			$keyStr = "eip712:" . strtolower($claim["signer"]);
			if (!in_array($keyStr, $keys)) $keys[] = $keyStr;
			sort($keys);
			self::ensureSorted($keys);
			while (count($sigs) < count($keys)) $sigs[] = null;
			$sigs[array_search($keyStr,$keys)] = EVM::sign($claim,$privateKey);

			return $claim + ["key"=>$keys,"sig"=>$sigs];
		}

		// ES256

		$pub = openssl_pkey_get_details(openssl_pkey_get_private($privateKey));
		$der = self::stripPem($pub["key"]);

		$keyStr = "data:key/es256;base64," . $der;

		if (!in_array($keyStr, $keys)) $keys[] = $keyStr;

		sort($keys);
		self::ensureUnique($keys);
		self::ensureSorted($keys);

		while (count($sigs) < count($keys)) $sigs[] = null;

		$index = array_search($keyStr, $keys);

		$tmp = $claim;
		$tmp["key"] = $keys;
		$tmp["sig"] = $sigs;

		$canon = self::canonicalize($tmp);

		openssl_sign($canon, $signature, $privateKey, OPENSSL_ALGO_SHA256);

		$sigs[$index] = base64_encode($signature);

		return $claim + ["key"=>$keys,"sig"=>$sigs];
	}

	// ---------- VERIFY ----------

	public static function verify($claim, $policy = []) {

		$keys = self::toArray($claim["key"] ?? []);
		$sigs = self::toArray($claim["sig"] ?? []);

		if (!$keys) {
			throw new Exception("OpenClaim: missing public keys");
		}

		self::ensureSorted($keys);

		$tmp = $claim;
		$tmp["key"] = $keys;
		$tmp["sig"] = $sigs;

		$canon = self::canonicalize($tmp);

		$valid = 0;

		foreach ($keys as $i => $k) {

			if (!isset($sigs[$i]) || $sigs[$i] === null) continue;

			$resolved = self::resolveKey($k);

			$keyObjs = is_array($resolved) && isset($resolved[0])
				? $resolved
				: [$resolved];

			foreach ($keyObjs as $ko) {

				if (!$ko || $ko["fmt"] !== "ES256") continue;

				$der = is_string($ko["value"])
					? $ko["value"]
					: base64_encode($ko["value"]);

				$pub = self::getCachedPublicKey($der);

				$ok = openssl_verify(
					$canon,
					base64_decode($sigs[$i]),
					$pub,
					OPENSSL_ALGO_SHA256
				);

				if ($ok === 1) {
					$valid++;
					break;
				}
			}
		}

		$minValid = $policy["minValid"] ?? 1;
		if (($policy["mode"] ?? "") === "all") {
			$minValid = count($keys);
		}

		return $valid >= $minValid;
	}
}