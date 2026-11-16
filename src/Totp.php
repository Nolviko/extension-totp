<?php

declare(strict_types=1);

namespace NolvikoExt\Totp;

use SensitiveParameter;

/**
 * Time-based one-time passwords (RFC 6238 over RFC 4226): HMAC-SHA1, 30-second steps, six digits, the form every
 * authenticator app supports. A code is accepted for the current step and one step either side (clock drift),
 * and only for a step later than the last accepted one, so a code works once.
 */
final class Totp
{
    public const PERIOD = 30;

    public const DIGITS = 6;

    private const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /** A new 160-bit secret in Base32 (32 characters), as authenticator apps expect it. */
    public static function newSecret(): string
    {
        return self::base32Encode(random_bytes(20));
    }

    public static function base32Encode(string $bytes): string
    {
        $bits = '';
        foreach (str_split($bytes) as $byte) {
            $bits .= str_pad(decbin(ord($byte)), 8, '0', STR_PAD_LEFT);
        }

        $text = '';
        foreach (str_split($bits, 5) as $chunk) {
            $text .= self::ALPHABET[bindec(str_pad($chunk, 5, '0'))];
        }

        return $text;
    }

    public static function base32Decode(#[SensitiveParameter] string $text): ?string
    {
        $text = strtoupper((string) preg_replace('/[\s=-]/', '', $text));
        if ($text === '' || strspn($text, self::ALPHABET) !== strlen($text)) {
            return null;
        }

        $bits = '';
        foreach (str_split($text) as $char) {
            $bits .= str_pad(decbin((int) strpos(self::ALPHABET, $char)), 5, '0', STR_PAD_LEFT);
        }

        $bytes = '';
        foreach (str_split(substr($bits, 0, intdiv(strlen($bits), 8) * 8), 8) as $byte) {
            $bytes .= chr((int) bindec($byte));
        }

        return $bytes;
    }

    /** The code for one time step (RFC 4226 dynamic truncation). */
    public static function code(#[SensitiveParameter] string $key, int $step): string
    {
        $hash = hash_hmac('sha1', pack('J', $step), $key, true);
        $offset = ord($hash[19]) & 0x0f;
        $value = ((ord($hash[$offset]) & 0x7f) << 24) | (ord($hash[$offset + 1]) << 16)
            | (ord($hash[$offset + 2]) << 8) | ord($hash[$offset + 3]);

        return str_pad((string) ($value % 10 ** self::DIGITS), self::DIGITS, '0', STR_PAD_LEFT);
    }

    /**
     * @param int $lastStep The step of the last accepted code (-1 for none).
     *
     * @return int|null The step the code belongs to, or null when it is wrong, too old or already used.
     */
    public static function match(
        #[SensitiveParameter] string $secret,
        #[SensitiveParameter] string $code,
        int $lastStep,
        int $now,
    ): ?int {
        $code = (string) preg_replace('/\s+/', '', $code);
        $key = self::base32Decode($secret);
        if ($key === null || preg_match('/^\d{' . self::DIGITS . '}$/D', $code) !== 1) {
            return null;
        }

        $current = intdiv($now, self::PERIOD);
        foreach ([$current, $current - 1, $current + 1] as $step) {
            if ($step > $lastStep && hash_equals(self::code($key, $step), $code)) {
                return $step;
            }
        }

        return null;
    }

    /** The otpauth:// address an authenticator app reads from the QR code. */
    public static function uri(string $issuer, string $account, #[SensitiveParameter] string $secret): string
    {
        $issuer = str_replace(':', '', $issuer);
        $label = rawurlencode($issuer) . ':' . rawurlencode(str_replace(':', '', $account));

        return 'otpauth://totp/' . $label . '?secret=' . $secret . '&issuer=' . rawurlencode($issuer)
            . '&algorithm=SHA1&digits=' . self::DIGITS . '&period=' . self::PERIOD;
    }
}
