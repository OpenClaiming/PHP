<?php
// Optional strict canonicalizer:
// composer require sop/json-canonicalization

class OpenClaim {

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

  public static function sign($claim, $privateKeyPem) {

    $canon = self::canonicalize($claim);

    openssl_sign(
      $canon,
      $signature,
      $privateKeyPem,
      OPENSSL_ALGO_SHA256
    );

    $out = $claim;
    $out["sig"] = base64_encode($signature);

    return $out;
  }

  public static function verify($claim, $publicKeyPem) {

    if (!isset($claim["sig"])) return false;

    $sig = base64_decode($claim["sig"]);

    $canon = self::canonicalize($claim);

    return openssl_verify(
      $canon,
      $sig,
      $publicKeyPem,
      OPENSSL_ALGO_SHA256
    ) === 1;
  }
}