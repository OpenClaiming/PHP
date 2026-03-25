<?php

/**
 * Q_OpenClaim — OpenClaiming Protocol (OCP) for PHP.
 *
 * Parity counterpart of the JS OpenClaim class (OpenClaim.js).
 * Same wire format, same key URI scheme, same canonicalization,
 * same signing model, same verification policy.
 *
 * Wire format:
 *   { ocp:1, iss, sub, stm, key:[], sig:[] }
 *
 * Key URI formats supported:
 *   data:key/es256;base64,<DER>       — inline P-256 public key
 *   data:key/eip712;<hex_address>     — Ethereum address
 *   https://example.com/keys#path     — URL-hosted key document
 *
 * Signing model:
 *   ES256:  openssl_sign($canon, $sig, $key, OPENSSL_ALGO_SHA256)
 *           — hashes the canonical string internally, byte-identical
 *             to Node crypto.sign("sha256", Buffer.from(canon), key)
 *             and browser subtle.sign({hash:"SHA-256"}, key, TextEncoder(canon)).
 *   EIP712: handled by Q_OpenClaim_EVM::sign()
 *
 * Canonicalization (RFC 8785 / JCS):
 *   - sig field always excluded
 *   - object keys sorted recursively (SORT_STRING, lexicographic)
 *   - numbers preserved as numbers (NOT converted to strings)
 *   - booleans preserved as booleans
 *   - Uses sop/json-canonicalization if available, otherwise fallback.
 *
 * Dependencies:
 *   OpenSSL (built-in)
 *   Optional: composer require sop/json-canonicalization
 *
 * @class Q_OpenClaim
 * @static
 */
class Q_OpenClaim
{
    // ─── Cache ───────────────────────────────────────────────────────────────

    private static $fetchCache     = [];
    private static $fetchCacheTime = [];
    private static $keyCache       = [];
    private static $pubKeyCache    = [];
    private static $fetchTtl       = 60; // seconds

    private static function fetchCached($url)
    {
        $now = time();
        if (
            isset(self::$fetchCache[$url]) &&
            ($now - self::$fetchCacheTime[$url]) < self::$fetchTtl
        ) {
            return self::$fetchCache[$url];
        }
        $data = @file_get_contents($url);
        self::$fetchCache[$url]     = $data;
        self::$fetchCacheTime[$url] = $now;
        return $data;
    }

    // ─── Canonicalization ────────────────────────────────────────────────────

    /**
     * Recursively sort object keys for canonical JSON.
     * RFC 8785 / JCS: numbers stay as numbers, booleans stay as booleans.
     * Only associative arrays (objects) have their keys sorted.
     * Sequential arrays (lists) preserve element order.
     * @private
     */
    private static function _normalize($v)
    {
        if (is_array($v)) {
            $isSeq = array_keys($v) === range(0, count($v) - 1);
            if (!$isSeq) {
                ksort($v, SORT_STRING);
            }
            foreach ($v as $k => $val) {
                $v[$k] = self::_normalize($val);
            }
        }
        return $v;
    }

    /**
     * Validate that no integers exceed PHP_INT_MAX / IEEE 754 safe range.
     * For uint256 EIP712 fields, callers must pass strings.
     * @private
     */
    private static function _validateNumbers($v, $path = 'claim')
    {
        if (is_array($v)) {
            foreach ($v as $k => $val) {
                self::_validateNumbers($val, $path . '.' . $k);
            }
            return;
        }
        // PHP integers are always safe (64-bit). Floats that are not finite are rejected.
        if (is_float($v) && !is_finite($v)) {
            throw new Exception("Q_OpenClaim: non-finite float at {$path} is not allowed");
        }
    }

    /**
     * Produce the canonical JSON string for signing/verification.
     * The `sig` field is always stripped before canonicalization.
     *
     * Uses sop/json-canonicalization (RFC 8785) if installed,
     * otherwise falls back to recursive ksort + json_encode.
     *
     * @method canonicalize
     * @static
     * @param {array} $claim
     * @return {string}
     */
    public static function canonicalize($claim)
    {
        $obj = $claim;
        unset($obj['sig']);

        if (class_exists('\\Sop\\JsonCanonicalization\\Canonicalizer')) {
            try {
                $c = new \Sop\JsonCanonicalization\Canonicalizer();
                return $c->canonicalize($obj);
            } catch (\Exception $e) {
                // fall through to fallback
            }
        }

        return json_encode(
            self::_normalize($obj),
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
        );
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private static function toArray($v)
    {
        if ($v === null) { return []; }
        return is_array($v) ? $v : [$v];
    }

    private static function normalizeSignatures($arr)
    {
        $arr = self::toArray($arr);
        $out = [];
        foreach ($arr as $v) {
            $out[] = ($v === null) ? null : (string)$v;
        }
        return $out;
    }

    private static function ensureSortedKeys($keys)
    {
        $sorted = $keys;
        sort($sorted, SORT_STRING);
        if ($sorted !== $keys) {
            throw new Exception('Q_OpenClaim: key array must be lexicographically sorted');
        }
    }

    private static function ensureUniqueKeys($keys)
    {
        if (count(array_unique($keys)) !== count($keys)) {
            throw new Exception('Q_OpenClaim: duplicate keys are not allowed');
        }
    }

    /**
     * Sort key+signature pairs together, maintaining index alignment.
     * Returns ['keys' => [...], 'signatures' => [...]].
     * @private
     */
    private static function buildSortedKeyState($keysInput, $sigsInput)
    {
        $keys = self::toArray($keysInput);
        $sigs = self::normalizeSignatures($sigsInput);

        self::ensureUniqueKeys($keys);

        if (count($sigs) > count($keys)) {
            throw new Exception('Q_OpenClaim: too many signatures');
        }

        $pairs = [];
        foreach ($keys as $i => $k) {
            $pairs[] = [
                'key' => $k,
                'sig' => ($i < count($sigs)) ? $sigs[$i] : null,
            ];
        }

        usort($pairs, function ($a, $b) { return strcmp($a['key'], $b['key']); });

        $sortedKeys = [];
        $sortedSigs = [];
        foreach ($pairs as $p) {
            $sortedKeys[] = $p['key'];
            $sortedSigs[] = $p['sig'];
        }

        self::ensureSortedKeys($sortedKeys);
        return ['keys' => $sortedKeys, 'signatures' => $sortedSigs];
    }

    private static function parseVerifyPolicy($policy, $totalKeys)
    {
        if ($policy === null)                                           { return ['minValid' => 1]; }
        if (is_int($policy))                                           { return ['minValid' => $policy]; }
        if (isset($policy['mode']) && $policy['mode'] === 'all')       { return ['minValid' => $totalKeys]; }
        if (isset($policy['minValid']) && is_int($policy['minValid'])) { return ['minValid' => $policy['minValid']]; }
        return ['minValid' => 1];
    }

    // ─── PEM / DER helpers ───────────────────────────────────────────────────

    private static function derToPem($base64Der)
    {
        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(trim($base64Der), 64, "\n")
            . "-----END PUBLIC KEY-----";
    }

    /**
     * Extract raw DER bytes from a PEM public key string.
     * @private
     */
    private static function _pemToDer($pem)
    {
        $b64 = preg_replace('/-----.*PUBLIC KEY-----|\\s+/', '', $pem);
        return base64_decode($b64);
    }

    private static function getCachedPublicKey($base64Der)
    {
        if (!isset(self::$pubKeyCache[$base64Der])) {
            self::$pubKeyCache[$base64Der] = self::derToPem($base64Der);
        }
        return self::$pubKeyCache[$base64Der];
    }

    // ─── data:key/ parser ────────────────────────────────────────────────────

    /**
     * Parse a data:key/ URI into ['fmt', 'value'].
     *
     * Formats:
     *   data:key/es256;base64,<DER>   → fmt=ES256, value=raw DER bytes (binary)
     *   data:key/eip712,<hex_address> → fmt=EIP712, value=address string
     *
     * @private
     */
    private static function parseDataKey($keyStr)
    {
        if (strpos($keyStr, 'data:key/') !== 0) { return null; }

        $idx = strpos($keyStr, ',');
        if ($idx === false) { return null; }

        $meta = substr($keyStr, 5, $idx - 5);   // e.g. "key/es256;base64"
        $data = substr($keyStr, $idx + 1);

        $parts    = explode(';', $meta);
        $fmt      = strtoupper(str_replace('key/', '', $parts[0]));
        $encoding = 'raw';

        foreach ($parts as $p) {
            if ($p === 'base64')    { $encoding = 'base64'; }
            if ($p === 'base64url') { $encoding = 'base64url'; }
        }

        if ($encoding === 'base64') {
            $data = base64_decode($data);
        } elseif ($encoding === 'base64url') {
            $data = base64_decode(strtr($data, '-_', '+/'));
        }

        return ['fmt' => $fmt, 'value' => $data];
    }

    // ─── Key resolution ──────────────────────────────────────────────────────

    /**
     * Resolve a key URI to ['fmt', 'value'].
     *
     * @method resolveKey
     * @static
     * @param {string} $keyStr
     * @param {array}  $seen   (internal, for cycle detection)
     * @return {array|null}
     */
    public static function resolveKey($keyStr, $seen = [])
    {
        if (in_array($keyStr, $seen, true)) {
            throw new Exception('Q_OpenClaim: cyclic key reference detected');
        }

        if (isset(self::$keyCache[$keyStr])) {
            return self::$keyCache[$keyStr];
        }

        $seen[] = $keyStr;

        // data:key/
        if (strpos($keyStr, 'data:key/') === 0) {
            $parsed = self::parseDataKey($keyStr);
            self::$keyCache[$keyStr] = $parsed;
            return $parsed;
        }

        // URL key document
        if (strpos($keyStr, 'http') === 0) {
            $parts   = explode('#', $keyStr);
            $url     = $parts[0];
            $raw     = self::fetchCached($url);
            if (!$raw) { return null; }

            $doc     = json_decode($raw, true);
            $current = $doc;

            foreach (array_slice($parts, 1) as $fragment) {
                if ($fragment === '') { continue; }
                $current = $current[$fragment] ?? null;
                if ($current === null) { return null; }
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

        // legacy shorthand: eip712:<address> or es256:<value>
        $colonIdx = strpos($keyStr, ':');
        if ($colonIdx === false) { return null; }

        $res = [
            'fmt'   => strtoupper(substr($keyStr, 0, $colonIdx)),
            'value' => substr($keyStr, $colonIdx + 1),
        ];
        self::$keyCache[$keyStr] = $res;
        return $res;
    }

    // ─── Sign ────────────────────────────────────────────────────────────────

    /**
     * Sign a claim with a private key, returning the claim with key/sig arrays updated.
     *
     * For ES256: signs SHA-256(canonicalize(claim)) using OPENSSL_ALGO_SHA256,
     *   byte-identical to Node crypto.sign("sha256", ...) and
     *   browser subtle.sign({hash:"SHA-256"}, key, TextEncoder(canon)).
     * For EIP712: delegates to Q_OpenClaim_EVM::sign().
     *
     * @method sign
     * @static
     * @param {array}  $claim
     * @param {mixed}  $privateKey  OpenSSL private key resource or PEM string
     * @param {array}  [$existing]  Existing keys/signatures to merge into
     * @return {array}
     */
    public static function sign($claim, $privateKey, $existing = [])
    {
        self::_validateNumbers($claim);

        $keys = self::toArray($existing['keys']       ?? ($claim['key'] ?? []));
        $sigs = self::normalizeSignatures($existing['signatures'] ?? ($claim['sig'] ?? []));

        $fmt = strtolower($claim['fmt'] ?? 'es256');

        // ── EIP712 ───────────────────────────────────────────────────────────
        if ($fmt === 'eip712') {
            $address = strtolower($claim['signer'] ?? '');
            $keyStr  = 'data:key/eip712,' . $address;

            if (!in_array($keyStr, $keys, true)) { $keys[] = $keyStr; }

            $state = self::buildSortedKeyState($keys, $sigs);
            $idx   = array_search($keyStr, $state['keys'], true);

            $state['signatures'][$idx] = Q_OpenClaim_EVM::sign($claim, $privateKey);

            return array_merge($claim, [
                'key' => $state['keys'],
                'sig' => $state['signatures']
            ]);
        }

        // ── ES256 ────────────────────────────────────────────────────────────
        $privKeyRes = is_string($privateKey)
            ? openssl_pkey_get_private($privateKey)
            : $privateKey;

        $details = openssl_pkey_get_details($privKeyRes);
        $pubDer  = base64_encode(self::_pemToDer($details['key']));
        $keyStr  = 'data:key/es256;base64,' . $pubDer;

        if (!in_array($keyStr, $keys, true)) { $keys[] = $keyStr; }

        $state = self::buildSortedKeyState($keys, $sigs);
        $idx   = array_search($keyStr, $state['keys'], true);

        $tmp        = $claim;
        $tmp['key'] = $state['keys'];
        $tmp['sig'] = $state['signatures'];

        $canon = self::canonicalize($tmp);

        // openssl_sign hashes internally with SHA-256 — matches Node and browser
        openssl_sign($canon, $sigRaw, $privKeyRes, OPENSSL_ALGO_SHA256);

        $state['signatures'][$idx] = base64_encode($sigRaw);

        return array_merge($claim, [
            'key' => $state['keys'],
            'sig' => $state['signatures']
        ]);
    }

    // ─── Verify ──────────────────────────────────────────────────────────────

    /**
     * Verify a claim's signatures against its key[] array.
     *
     * @method verify
     * @static
     * @param {array}      $claim
     * @param {int|array}  [$policy]
     * @return {bool}
     */
    public static function verify($claim, $policy = null)
    {
        $keys = self::toArray($claim['key'] ?? []);
        $sigs = self::normalizeSignatures($claim['sig'] ?? []);

        if (!$keys) {
            throw new Exception('Q_OpenClaim: missing public keys');
        }

        $state = self::buildSortedKeyState($keys, $sigs);

        $tmp        = $claim;
        $tmp['key'] = $state['keys'];
        $tmp['sig'] = $state['signatures'];

        $canon = self::canonicalize($tmp);
        $valid = 0;

        foreach ($state['keys'] as $i => $k) {
            $sig = $state['signatures'][$i] ?? null;
            if (!$sig) { continue; }

            $resolved = self::resolveKey($k);
            if (!$resolved) { continue; }

            // resolveKey may return a list of key objects (URL document)
            $keyObjs = (isset($resolved[0]) && is_array($resolved[0]))
                ? $resolved
                : [$resolved];

            foreach ($keyObjs as $ko) {
                if (!$ko) { continue; }

                $koFmt = strtoupper($ko['fmt'] ?? '');

                // ── EIP712 ───────────────────────────────────────────────────
                if ($koFmt === 'EIP712') {
                    try {
                        if (Q_OpenClaim_EVM::verify($claim, $sig, $ko['value'])) {
                            $valid++;
                            break;
                        }
                    } catch (Exception $e) { /* try next */ }
                    continue;
                }

                // ── ES256 ────────────────────────────────────────────────────
                if ($koFmt !== 'ES256') { continue; }

                // $ko['value'] is raw DER bytes (parseDataKey base64-decoded it).
                // base64-encode for PEM wrapping.
                $base64Der = base64_encode($ko['value']);
                $pubPem    = self::getCachedPublicKey($base64Der);

                $ok = openssl_verify(
                    $canon,
                    base64_decode($sig),
                    $pubPem,
                    OPENSSL_ALGO_SHA256
                );

                if ($ok === 1) {
                    $valid++;
                    break;
                }
            }
        }

        $p = self::parseVerifyPolicy($policy, count($state['keys']));
        return $valid >= $p['minValid'];
    }
}
