<?php

declare(strict_types=1);

/*
 * Nolviko TOTP extension (2026-11-15): authenticator-app codes as a second sign-in step. Registers the method
 * with core (which stores the sealed secret, recovery codes and attempts) and the member's setup page.
 */

use Nolviko\Core\Extensions\ExtensionContext;
use Nolviko\Core\Extensions\ExtensionProvider;
use Nolviko\Core\Locale\MessageTranslator;
use Nolviko\Core\Routing\RouteDefinition;
use Nolviko\Core\Routing\Router;
use Nolviko\Core\Session\CsrfTokens;
use Nolviko\Core\Session\Session;
use Nolviko\Core\Settings\SiteSettings;
use Nolviko\Core\View\TemplateRenderer;
use Nolviko\Modules\Permissions\Domain\PermissionDefinition;
use Nolviko\Modules\Permissions\Domain\PermissionType;
use Nolviko\Modules\Users\Domain\LoginThrottle;
use Nolviko\Modules\Users\Domain\PasswordHasher;
use Nolviko\Modules\Users\Domain\SecondFactors;
use Nolviko\Modules\Users\Domain\UserRepository;
use Nolviko\Modules\Users\Http\AuthSession;
use NolvikoExt\Totp\SetupHandler;
use NolvikoExt\Totp\TotpFactor;

require_once __DIR__ . '/Totp.php';
require_once __DIR__ . '/QrCode.php';
require_once __DIR__ . '/TotpFactor.php';
require_once __DIR__ . '/SetupHandler.php';

return new class implements ExtensionProvider {
    public function register(ExtensionContext $context): void
    {
        // Every member may open the setup page (guests are sent to the login there).
        $context->permission(new PermissionDefinition('nolviko.totp.use', PermissionType::Bool, default: true));
        $context->service(TotpFactor::ID, static fn(): TotpFactor => new TotpFactor());
        $context->secondFactor(TotpFactor::ID);
        $context->route(
            new RouteDefinition(
                'nolviko.totp.setup',
                '/extensions/nolviko/totp/setup',
                ['GET', 'POST'],
                requiresHttps: true,
            ),
            'nolviko.totp.use',
            static fn(
                MessageTranslator $translator,
                TemplateRenderer $views,
                AuthSession $auth,
                Session $session,
                SecondFactors $factors,
                UserRepository $users,
                PasswordHasher $hasher,
                CsrfTokens $csrf,
                Router $router,
                LoginThrottle $throttle,
                SiteSettings $site,
            ): SetupHandler => new SetupHandler(
                $translator,
                $views,
                $auth,
                $session,
                $factors,
                $users,
                $hasher,
                $csrf,
                $router,
                $throttle,
                $site,
            ),
            [
                MessageTranslator::class,
                TemplateRenderer::class,
                AuthSession::class,
                Session::class,
                SecondFactors::class,
                UserRepository::class,
                PasswordHasher::class,
                CsrfTokens::class,
                Router::class,
                LoginThrottle::class,
                SiteSettings::class,
            ],
        );
    }
};
