<?php

/**
 * Q_OpenClaim_EVM — EIP-712 Payment and Authorization extensions for OCP (PHP).
 *
 * Parity counterpart of Q.OpenClaim.EVM (JS).
 *
 * Dependencies — NO web3.php or kornrunner/keccak required:
 *   Q_Crypto_EIP712  — canonical EIP-712 digest (uses Crypto\Keccak, already a Q dep)
 *   Crypto\Keccak    — already a Q dep (mdanter/phpecc)
 *   GMP extension    — already required by Q for big integer arithmetic
 *
 * PHP is primarily the verifier in the Safe plugin context (Jets verify
 * payment claims from browsers). Signing is done by wallets (MetaMask,
 * hardware). For server-side signing pass a callable to sign().
 *
 * @class Q_OpenClaim_EVM
 * @static
 */
class Q_OpenClaim_EVM
{
    // ─── Type definitions ─────────────────────────────────────────────────────

    public static $PAYMENT_TYPES = [
        'EIP712Domain' => [
            ['name' => 'name',              'type' => 'string'],
            ['name' => 'version',           'type' => 'string'],
            ['name' => 'chainId',           'type' => 'uint256'],
            ['name' => 'verifyingContract', 'type' => 'address'],
        ],
        'Payment' => [
            ['name' => 'payer',          'type' => 'address'],
            ['name' => 'token',          'type' => 'address'],
            ['name' => 'recipientsHash', 'type' => 'bytes32'],
            ['name' => 'max',            'type' => 'uint256'],
            ['name' => 'line',           'type' => 'uint256'],
            ['name' => 'nbf',            'type' => 'uint256'],
            ['name' => 'exp',            'type' => 'uint256'],
        ],
    ];

    public static $AUTHORIZATION_TYPES = [
        'EIP712Domain' => [
            ['name' => 'name',              'type' => 'string'],
            ['name' => 'version',           'type' => 'string'],
            ['name' => 'chainId',           'type' => 'uint256'],
            ['name' => 'verifyingContract', 'type' => 'address'],
        ],
        'Authorization' => [
            ['name' => 'authority',       'type' => 'address'],
            ['name' => 'subject',         'type' => 'address'],
            ['name' => 'actorsHash',      'type' => 'bytes32'],
            ['name' => 'rolesHash',       'type' => 'bytes32'],
            ['name' => 'actionsHash',     'type' => 'bytes32'],
            ['name' => 'constraintsHash', 'type' => 'bytes32'],
            ['name' => 'contextsHash',    'type' => 'bytes32'],
            ['name' => 'nbf',             'type' => 'uint256'],
            ['name' => 'exp',             'type' => 'uint256'],
        ],
    ];

    // ─── Helpers ──────────────────────────────────────────────────────────────

    private static function toArray($v)
    {
        if ($v === null) { return []; }
        return is_array($v) ? $v : [$v];
    }

    private static function lower($v) { return strtolower((string)$v); }

    private static function readField($claim, $key, $fallback = null)
    {
        if (isset($claim[$key]))        { return $claim[$key]; }
        if (isset($claim['stm'][$key])) { return $claim['stm'][$key]; }
        return $fallback;
    }

    // ─── keccak256 via Crypto\Keccak (already a Q dep) ───────────────────────

    private static function keccak256(string $data): string
    {
        return \Crypto\Keccak::hash($data, 256, true); // true = raw binary output
    }

    // ─── ABI encoding helpers ─────────────────────────────────────────────────

    private static function padLeft32(string $b): string
    {
        if (strlen($b) > 32) { throw new \Exception('Q_OpenClaim_EVM: value exceeds 32 bytes'); }
        return str_pad($b, 32, "\x00", STR_PAD_LEFT);
    }

    private static function encodeAddress(string $addr): string
    {
        $hex = str_pad(strtolower(str_replace('0x', '', $addr)), 40, '0', STR_PAD_LEFT);
        return self::padLeft32(hex2bin($hex));
    }

    // ─── Hash helpers (public — parity with JS) ───────────────────────────────

    public static function hashRecipients($recipients): string
    {
        $addrs = self::toArray($recipients);
        if (!$addrs) { return self::keccak256(''); }
        return self::keccak256(
            implode('', array_map([self::class, 'encodeAddress'], $addrs))
        );
    }

    public static function hashActors($actors): string
    {
        $addrs = self::toArray($actors);
        if (!$addrs) { return self::keccak256(''); }
        return self::keccak256(
            implode('', array_map([self::class, 'encodeAddress'], $addrs))
        );
    }

    public static function hashStringArray($strings): string
    {
        $arr = self::toArray($strings);
        if (!$arr) { return self::keccak256(''); }
        $hashes = array_map(
            function ($s) { return self::keccak256((string)$s); },
            $arr
        );
        return self::keccak256(implode('', $hashes));
    }

    public static function hashConstraint(array $c): string
    {
        $th = self::keccak256('Constraint(string key,string op,string value)');
        return self::keccak256(
            $th
            . self::keccak256($c['key']   ?? '')
            . self::keccak256($c['op']    ?? '')
            . self::keccak256($c['value'] ?? '')
        );
    }

    public static function hashConstraints($constraints): string
    {
        $arr = self::toArray($constraints);
        if (!$arr) { return self::keccak256(''); }
        return self::keccak256(
            implode('', array_map([self::class, 'hashConstraint'], $arr))
        );
    }

    public static function hashContext(array $ctx): string
    {
        $th = self::keccak256('Context(string type,string value)');
        return self::keccak256(
            $th
            . self::keccak256($ctx['type']  ?? $ctx['fmt'] ?? '')
            . self::keccak256($ctx['value'] ?? '')
        );
    }

    public static function hashContexts($contexts): string
    {
        $arr = self::toArray($contexts);
        if (!$arr) { return self::keccak256(''); }
        return self::keccak256(
            implode('', array_map([self::class, 'hashContext'], $arr))
        );
    }

    // ─── Extension detection ─────────────────────────────────────────────────

    public static function detectExtension(array $claim): ?string
    {
        $payer = self::readField($claim, 'payer');
        $token = self::readField($claim, 'token');
        $line  = self::readField($claim, 'line');
        if ($payer !== null && $token !== null && $line !== null) { return 'payment'; }

        $authority = self::readField($claim, 'authority');
        $subject   = self::readField($claim, 'subject');
        if ($authority && $subject) { return 'authorization'; }

        return null;
    }

    // ─── Payload builders ─────────────────────────────────────────────────────

    public static function toPaymentPayload(array $claim): array
    {
        $recipients = self::toArray(self::readField($claim, 'recipients', []));
        return [
            'primaryType' => 'Payment',
            'domain'      => [
                'name'              => 'OpenClaiming.payments',
                'version'           => '1',
                'chainId'           => $claim['chainId'],
                'verifyingContract' => $claim['contract'],
            ],
            'types' => self::$PAYMENT_TYPES,
            'value' => [
                'payer'          => self::lower(self::readField($claim, 'payer', '')),
                'token'          => self::lower(self::readField($claim, 'token', '')),
                'recipientsHash' => self::hashRecipients($recipients),
                'max'            => (int)self::readField($claim, 'max',  0),
                'line'           => (int)self::readField($claim, 'line', 0),
                'nbf'            => (int)self::readField($claim, 'nbf',  0),
                'exp'            => (int)self::readField($claim, 'exp',  0),
            ],
            'data' => ['recipients' => $recipients],
        ];
    }

    public static function toAuthorizationPayload(array $claim): array
    {
        $actors      = self::toArray(self::readField($claim, 'actors',      []));
        $roles       = self::toArray(self::readField($claim, 'roles',       []));
        $actions     = self::toArray(self::readField($claim, 'actions',     []));
        $constraints = self::toArray(self::readField($claim, 'constraints', []));
        $contexts    = self::toArray(self::readField($claim, 'contexts',    []));

        return [
            'primaryType' => 'Authorization',
            'domain'      => [
                'name'              => 'OpenClaiming.authorizations',
                'version'           => '1',
                'chainId'           => $claim['chainId'],
                'verifyingContract' => $claim['contract'],
            ],
            'types' => self::$AUTHORIZATION_TYPES,
            'value' => [
                'authority'       => self::lower(self::readField($claim, 'authority', '')),
                'subject'         => self::lower(self::readField($claim, 'subject',   '')),
                'actorsHash'      => self::hashActors($actors),
                'rolesHash'       => self::hashStringArray($roles),
                'actionsHash'     => self::hashStringArray($actions),
                'constraintsHash' => self::hashConstraints($constraints),
                'contextsHash'    => self::hashContexts($contexts),
                'nbf'             => (int)self::readField($claim, 'nbf', 0),
                'exp'             => (int)self::readField($claim, 'exp', 0),
            ],
            'data' => compact('actors', 'roles', 'actions', 'constraints', 'contexts'),
        ];
    }

    public static function toPayload(array $claim): array
    {
        $ext = self::detectExtension($claim);
        if ($ext === 'payment')       { return self::toPaymentPayload($claim); }
        if ($ext === 'authorization') { return self::toAuthorizationPayload($claim); }
        throw new \Exception('Q_OpenClaim_EVM: unable to detect claim extension');
    }

    // ─── hashTypedData — delegates to Q_Crypto_EIP712 ────────────────────────

    /**
     * Compute the EIP-712 typed-data digest for a claim.
     * Returns raw 32 bytes.
     *
     * Delegates to Q_Crypto_EIP712::hashTypedData() which uses Crypto\Keccak —
     * already a Q dependency. No web3.php or kornrunner needed.
     *
     * @method hashTypedData
     * @static
     * @param {array} $claim
     * @return {string} 32 raw bytes
     */
    public static function hashTypedData(array $claim): string
    {
        $payload = self::toPayload($claim);
        return Q_Crypto_EIP712::hashTypedData(
            $payload['domain'],
            $payload['primaryType'],
            $payload['value'],
            $payload['types']
        );
    }

    // ─── Sign ─────────────────────────────────────────────────────────────────

    /**
     * Sign a claim. $signer is a callable receiving raw 32-byte digest
     * and returning a 65-byte hex signature (0x-prefixed, r||s||v).
     *
     * @method sign
     * @static
     * @param {array}    $claim
     * @param {callable} $signer  function(string $digest32bytes): string
     * @return {string}  65-byte hex (0x-prefixed)
     */
    public static function sign(array $claim, callable $signer): string
    {
        return call_user_func($signer, self::hashTypedData($claim));
    }

    // ─── Verify ───────────────────────────────────────────────────────────────

    /**
     * Recover the Ethereum signer address from a claim + signature.
     *
     * Delegates to Crypto\Signature::recoverPublicKey() (mdanter/phpecc,
     * already a Q dependency) — no new deps, no hand-rolled curve math.
     * Byte-identical to the JS @noble/secp256k1-based recovery.
     *
     * @method recoverSigner
     * @static
     * @param {array}  $claim
     * @param {string} $signature  65-byte hex (0x-prefixed), r||s||v
     * @return {string} Ethereum address (0x-prefixed, lowercase)
     */
    public static function recoverSigner(array $claim, string $signature): string
    {
        return self::_ecrecover(self::hashTypedData($claim), $signature);
    }

    public static function verify(array $claim, string $signature, string $expectedAddress): bool
    {
        try {
            return self::lower(self::recoverSigner($claim, $signature))
                === self::lower($expectedAddress);
        } catch (\Exception $e) {
            return false;
        }
    }

    public static function verifyPayment(array $claim, string $sig, string $addr): bool
    {
        return self::verify($claim, $sig, $addr);
    }

    public static function verifyAuthorization(array $claim, string $sig, string $addr): bool
    {
        return self::verify($claim, $sig, $addr);
    }

    // ─── hashTypedDataHex — convenience, returns 0x hex for wallet APIs ─────────

    /**
     * Compute the EIP-712 typed-data digest for a claim, returned as
     * a 0x-prefixed 64-char hex string (32 bytes).
     *
     * Useful for passing directly to MetaMask, hardware wallets, or
     * Crypto\EthSigRecover::ecRecover().
     *
     * @method hashTypedDataHex
     * @static
     * @param {array} $claim
     * @return {string} 0x-prefixed hex digest
     */
    public static function hashTypedDataHex(array $claim): string
    {
        return '0x' . bin2hex(self::hashTypedData($claim));
    }

    // ─── ecRecover — standalone helper wrapping Crypto\EthSigRecover ─────────

    /**
     * Recover an Ethereum address from a raw 32-byte digest + EIP-712 signature.
     *
     * This is a standalone helper — no claim object required. Use it when you
     * have the digest and signature separately, e.g. verifying a MetaMask
     * eth_signTypedData_v4 response after computing the digest yourself.
     *
     * Delegates to Crypto\EthSigRecover::ecRecover() (mdanter/phpecc, already
     * a Q dep) via Crypto\Signature::recoverPublicKey() and Crypto\Keccak.
     * No new external dependencies.
     *
     * @method ecRecover
     * @static
     * @param {string} $digest     Raw 32-byte binary OR 0x-prefixed hex digest
     * @param {string} $signature  65-byte hex (0x-prefixed), r||s||v, v=27|28
     * @return {string} 0x-prefixed lowercase Ethereum address
     */
    public static function ecRecover(string $digest, string $signature): string
    {
        $hexDigest = (strpos($digest, '0x') === 0)
            ? $digest
            : '0x' . bin2hex($digest);

        $sig = (strpos($signature, '0x') === 0) ? $signature : '0x' . $signature;
        if (strlen($sig) !== 132) {
            throw new \Exception('Q_OpenClaim_EVM::ecRecover: invalid signature length');
        }

        $recover = new \Crypto\EthSigRecover();
        return $recover->ecRecover($hexDigest, $sig);
    }

    // ─── _ecrecover (private) — called by recoverSigner() ────────────────────

    /**
     * Internal: build the EIP-712 digest for a claim, then run ecRecover.
     * @private
     */
    private static function _ecrecover(string $digest, string $signature): string
    {
        $sig = (strpos($signature, '0x') === 0) ? $signature : '0x' . $signature;
        if (strlen($sig) !== 132) {
            throw new \Exception('Q_OpenClaim_EVM: invalid signature length (expected 65 bytes)');
        }
        $hexDigest = '0x' . bin2hex($digest);
        $recover   = new \Crypto\EthSigRecover();
        return $recover->ecRecover($hexDigest, $sig);
    }
}
