<?php
// Optional strict canonicalizer:
// composer require sop/json-canonicalization

class OpenClaim {

	// ---------- CACHE ----------

	private static $fetchCache = [];
	private static $fetchCacheTime = [];
	private static $fetchTtl = 300; // seconds

	private static function fetchCached($url) {

		$now = time();

		// IMPORTANT: use array_key_exists to allow null/false caching
		if (array_key_exists($url, self::$fetchCache)) {
			$t = self::$fetchCacheTime[$url] ?? 0;
			if (($now - $t) < self::$fetchTtl) {
				return self::$fetchCache[$url];
			}
		}

		$data = null;

		try {
			$data = @file_get_contents($url);
		} catch (\Exception $e) {}

		// cache even failures (false/null)
		self::$fetchCache[$url] = $data;
		self::$fetchCacheTime[$url] = $now;

		return $data;
	}

	public static function clearFetchCache($url = null) {
		if ($url === null) {
			self::$fetchCache = [];
			self::$fetchCacheTime = [];
		} else {
			unset(self::$fetchCache[$url]);
			unset(self::$fetchCacheTime[$url]);
		}
	}

	private static function normalize($v) {

		if (is_array($v)) {

			// associative array
			if (array_keys($v) !== range(0, count($v)-1)) {
				ksort($v);
			}

			foreach ($v as $k => $val) {
				$v[$k] = self::normalize($val);
			}

			return $v;
		}

		return $v;
	}

	private static function fallbackCanonicalize($claim) {

		unset($claim["sig"]);

		$sorted = self::normalize($claim);

		return json_encode(
			$sorted,
			JSON_UNESCAPED_SLASHES
		);
	}

	public static function canonicalize($claim) {

		$obj = $claim;
		unset($obj["sig"]);

		// Try RFC8785 canonicalization if library installed
		if (class_exists("\\Sop\\JsonCanonicalization\\Canonicalizer")) {

			try {
				$canon = new \Sop\JsonCanonicalization\Canonicalizer();
				return $canon->canonicalize($obj);
			} catch (\Exception $e) {}
		}

		return self::fallbackCanonicalize($claim);
	}

	// ---------- NEW HELPERS ----------

	private static function toArray($v) {
		if ($v === null) return [];
		return is_array($v) ? $v : [$v];
	}

	private static function ensureSorted($keys) {
		$sorted = $keys;
		sort($sorted, SORT_STRING);
		if ($sorted !== $keys) {
			throw new Exception("keys must be lexicographically sorted");
		}
	}

	private static function pemToDer($pem) {
		return preg_replace(
			"/-----BEGIN PUBLIC KEY-----|-----END PUBLIC KEY-----|\\s+/",
			"",
			$pem
		);
	}

	private static function derToPem($base64) {
		$body = chunk_split($base64, 64, "\n");
		return "-----BEGIN PUBLIC KEY-----\n" .
			   $body .
			   "-----END PUBLIC KEY-----\n";
	}

	private static function resolveKey($keyStr) {

		if (!is_string($keyStr)) return null;

		$parts = explode(":", $keyStr, 2);
		if (count($parts) < 2) return null;

		$typ = strtoupper($parts[0]);
		$rest = $parts[1];

		if (strpos($rest, "http://") === 0 ||
			strpos($rest, "https://") === 0) {

			$segments = explode("#", $rest);
			$url = $segments[0];

			$raw = self::fetchCached($url);

			if ($raw === false || $raw === null) return null;

			$json = json_decode($raw, true);

			if (json_last_error() !== JSON_ERROR_NONE) return null;

			$current = $json;

			for ($i = 1; $i < count($segments); $i++) {
				$key = $segments[$i];
				if (!$key) continue;

				// safer traversal
				if (!is_array($current) || !array_key_exists($key, $current)) {
					return null;
				}

				$current = $current[$key];
			}

			return ["typ" => $typ, "value" => $current];
		}

		return ["typ" => $typ, "value" => $rest];
	}

	// ---------- SIGN ----------

	public static function sign($claim, $privateKeyPem) {
		return self::signWithExisting($claim, $privateKeyPem, []);
	}

	public static function signWithExisting($claim, $privateKeyPem, $existing) {

		$keys = self::toArray($existing["keys"] ?? ($claim["key"] ?? []));
		$sigs = self::toArray($existing["signatures"] ?? ($claim["sig"] ?? []));

		$pub = openssl_pkey_get_details(
			openssl_pkey_get_private($privateKeyPem)
		);

		$pubPem = $pub["key"];
		$keyStr = "es256:" . self::pemToDer($pubPem);

		if (!in_array($keyStr, $keys)) {
			$keys[] = $keyStr;
		}

		sort($keys, SORT_STRING);
		self::ensureSorted($keys);

		while (count($sigs) < count($keys)) {
			$sigs[] = null;
		}

		$index = array_search($keyStr, $keys);

		$tmp = $claim;
		$tmp["key"] = $keys;
		$tmp["sig"] = $sigs;

		$canon = self::canonicalize($tmp);

		openssl_sign(
			$canon,
			$signature,
			$privateKeyPem,
			OPENSSL_ALGO_SHA256
		);

		$sigs[$index] = base64_encode($signature);

		$out = $claim;
		$out["key"] = $keys;
		$out["sig"] = $sigs;

		return $out;
	}

	// ---------- VERIFY ----------

	public static function verify($claim, $publicKeyPem) {
		return self::verifyWithPolicy($claim, $publicKeyPem, []);
	}

	public static function verifyWithPolicy($claim, $publicKeyPem, $policy) {

		$keys = self::toArray($claim["key"] ?? []);
		$sigs = self::toArray($claim["sig"] ?? []);

		if (!$keys || !$sigs) return false;
		if (count($keys) !== count($sigs)) return false;

		self::ensureSorted($keys);

		$tmp = $claim;
		$tmp["key"] = $keys;
		$tmp["sig"] = $sigs;

		$canon = self::canonicalize($tmp);

		$valid = 0;

		foreach ($keys as $i => $k) {

			$sigB64 = $sigs[$i];
			if ($sigB64 === null) continue;

			$keyObj = self::resolveKey($k);
			if (!$keyObj) continue;

			if ($keyObj["typ"] === "EIP712") continue;
			if ($keyObj["typ"] !== "ES256") continue;

			$pubPem = self::derToPem($keyObj["value"]);

			$ok = openssl_verify(
				$canon,
				base64_decode($sigB64),
				$pubPem,
				OPENSSL_ALGO_SHA256
			);

			if ($ok === 1) {
				$valid++;
			}
		}

		$minValid = $policy["minValid"] ?? 1;

		if (($policy["mode"] ?? "") === "all") {
			$minValid = count($keys);
		}

		return $valid >= $minValid;
	}
}