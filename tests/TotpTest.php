<?php

declare(strict_types=1);

namespace NolvikoExt\Totp\Tests;

use NolvikoExt\Totp\QrCode;
use NolvikoExt\Totp\Totp;
use NolvikoExt\Totp\TotpFactor;
use Nolviko\Core\Extensions\AuthChallenge;
use PHPUnit\Framework\TestCase;

/**
 * Run from the workspace root (not part of the ZIP):
 *   php dev/vendor/bin/phpunit --bootstrap dev/vendor/autoload.php extensions-src/nolviko/totp/tests
 * The QR encoder was also compared bit for bit with the Python `qrcode` library for versions 1-13 and all eight
 * masks (2026-11-15); the fingerprints below pin that output.
 */
final class TotpTest extends TestCase
{
    private const RFC_SECRET = '12345678901234567890';

    public static function setUpBeforeClass(): void
    {
        require_once dirname(__DIR__) . '/src/Totp.php';
        require_once dirname(__DIR__) . '/src/QrCode.php';
        require_once dirname(__DIR__) . '/src/TotpFactor.php';
    }

    public function testRfc6238VectorsAndBase32(): void
    {
        // RFC 6238 appendix B (SHA-1), last six digits.
        self::assertSame('287082', Totp::code(self::RFC_SECRET, intdiv(59, 30)));
        self::assertSame('081804', Totp::code(self::RFC_SECRET, intdiv(1111111109, 30)));
        self::assertSame('279037', Totp::code(self::RFC_SECRET, intdiv(2000000000, 30)));
        self::assertSame('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', Totp::base32Encode(self::RFC_SECRET));
        self::assertSame(self::RFC_SECRET, Totp::base32Decode('gezd gnbv gy3t qojq gezd gnbv gy3t qojq'));
        self::assertNull(Totp::base32Decode('not base32!'));
        self::assertSame(32, strlen(Totp::newSecret()));
    }

    public function testACodeIsAcceptedOnceAndOnlyNearItsTime(): void
    {
        $secret = Totp::base32Encode(self::RFC_SECRET);
        $now = 1000 * 30 + 5;
        $code = Totp::code(self::RFC_SECRET, 1000);

        self::assertSame(1000, Totp::match($secret, $code, -1, $now));
        self::assertSame(1000, Totp::match($secret, $code, -1, $now + 30), 'one step of drift');
        self::assertNull(Totp::match($secret, $code, -1, $now + 60));
        self::assertNull(Totp::match($secret, $code, 1000, $now), 'already used');
        self::assertNull(Totp::match($secret, '12345', -1, $now));

        $factor = new TotpFactor(static fn(): int => $now);
        $challenge = new AuthChallenge('nolviko/totp', 7, 'sign_in', str_repeat('a', 64), $now + 300);
        $spaced = substr($code, 0, 3) . ' ' . substr($code, 3);
        $next = $factor->verify($challenge, TotpFactor::state($secret, -1), $spaced);
        self::assertSame(TotpFactor::state($secret, 1000), $next);
        self::assertNull($factor->verify($challenge, (string) $next, $code));
        self::assertNull($factor->verify($challenge, 'not json', $code));
    }

    public function testOtpauthUriAndQrCode(): void
    {
        $uri = Totp::uri('My: Forum', 'ali:veli', 'JBSWY3DPEHPK3PXP');
        self::assertSame(
            'otpauth://totp/My%20Forum:aliveli?secret=JBSWY3DPEHPK3PXP&issuer=My%20Forum'
                . '&algorithm=SHA1&digits=6&period=30',
            $uri,
        );

        $matrix = QrCode::matrix('hello world', 0);
        self::assertCount(21, $matrix);
        $bits = array_map(
            static fn(array $row): string => implode('', array_map(static fn(bool $d): string => $d ? '1' : '0', $row)),
            $matrix,
        );
        self::assertSame('ffff541808845d56', substr(hash('sha256', implode("\n", $bits)), 0, 16));
        self::assertCount(49, QrCode::matrix(Totp::uri('Nolviko Test Forum', 'ergezcaner', str_repeat('A', 32))));
        self::assertStringStartsWith('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 29 29"', QrCode::svg('a'));
    }
}
