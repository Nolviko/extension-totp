<?php

declare(strict_types=1);

namespace NolvikoExt\Totp;

use Closure;
use Nolviko\Core\Extensions\AuthChallenge;
use Nolviko\Core\Extensions\SecondFactorProvider;
use SensitiveParameter;

/**
 * The authenticator-app method. Its state (kept and sealed by core) is the member's secret and the last accepted
 * time step; a successful check returns the state with the new step, which makes every code single-use.
 */
final class TotpFactor implements SecondFactorProvider
{
    public const ID = 'nolviko.totp.factor';

    private readonly Closure $clock;

    /** @param (Closure(): int)|null $clock Unix time. */
    public function __construct(?Closure $clock = null)
    {
        $this->clock = $clock ?? time(...);
    }

    public function label(): string
    {
        return 'nolviko.totp.label';
    }

    public function setupRoute(): string
    {
        return 'nolviko.totp.setup';
    }

    public function verify(
        AuthChallenge $challenge,
        #[SensitiveParameter] string $state,
        #[SensitiveParameter] string $response,
    ): ?string {
        $data = json_decode($state, true, 4);
        if (!is_array($data) || !is_string($data['secret'] ?? null) || !is_int($data['step'] ?? null)) {
            return null;
        }

        $step = Totp::match($data['secret'], $response, $data['step'], ($this->clock)());

        return $step === null ? null : self::state($data['secret'], $step);
    }

    public static function state(#[SensitiveParameter] string $secret, int $step): string
    {
        return json_encode(['secret' => $secret, 'step' => $step], JSON_THROW_ON_ERROR);
    }
}
