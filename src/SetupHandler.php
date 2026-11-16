<?php

declare(strict_types=1);

namespace NolvikoExt\Totp;

use Nolviko\Core\Http\InstallerPage;
use Nolviko\Core\Http\RouteHandler;
use Nolviko\Core\Locale\MessageTranslator;
use Nolviko\Core\Routing\CoreRoutes;
use Nolviko\Core\Routing\UrlGenerator;
use Nolviko\Core\Session\CsrfTokens;
use Nolviko\Core\Session\Session;
use Nolviko\Core\Settings\SiteSettings;
use Nolviko\Core\View\SafeHtml;
use Nolviko\Core\View\TemplateRenderer;
use Nolviko\Modules\Users\Domain\LoginThrottle;
use Nolviko\Modules\Users\Domain\PasswordHasher;
use Nolviko\Modules\Users\Domain\SecondFactors;
use Nolviko\Modules\Users\Domain\UserRepository;
use Nolviko\Modules\Users\Http\AuthSession;
use Nolviko\Modules\Users\Http\LoginVerifyHandler;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * `/extensions/nolviko/totp/setup`: a member turns the authenticator app on (scan, confirm with a first code,
 * receive recovery codes once), gets new recovery codes (with a code) or turns it off (password and code).
 * Every code check goes through core (throttled per member like the sign-in step). Page text is translated
 * and every value is escaped here, because the page body reaches the template as SafeHtml.
 */
final class SetupHandler implements RouteHandler
{
    private const PENDING_KEY = '_nolviko_totp_pending';

    private const PENDING_SECONDS = 1800;

    public function __construct(
        private readonly MessageTranslator $translator,
        private readonly TemplateRenderer $views,
        private readonly AuthSession $auth,
        private readonly Session $session,
        private readonly SecondFactors $factors,
        private readonly UserRepository $users,
        private readonly PasswordHasher $hasher,
        private readonly CsrfTokens $csrf,
        private readonly UrlGenerator $urls,
        private readonly LoginThrottle $throttle,
        private readonly SiteSettings $site,
    ) {
    }

    public function handle(Request $request, array $parameters): Response
    {
        $userId = $this->auth->userId($request);
        $user = $userId === null ? null : $this->users->findById($userId);
        if ($user === null) {
            return InstallerPage::redirect($this->urls->generate(CoreRoutes::LOGIN));
        }

        $enrolled = $this->factors->enrolled($user->id, TotpFactor::ID);
        if (!$request->isMethod('POST')) {
            return $enrolled ? $this->status($user->id, null) : $this->setup($user->id, $user->username, null);
        }

        $input = $request->request->all();
        $field = static fn(string $name): string => is_string($input[$name] ?? null) ? $input[$name] : '';
        $identifier = LoginVerifyHandler::THROTTLE_PREFIX . $user->id;
        $wait = $this->throttle->retryAfter($identifier, $request->getClientIp());
        if ($wait > 0) {
            $error = $this->translator->translate('diagnostics.login_throttled', [
                'minutes' => (int) ceil($wait / 60),
            ]);

            return $enrolled
                ? $this->status($user->id, $error, 429)
                : $this->setup($user->id, $user->username, $error, 429);
        }

        switch ($enrolled ? $field('action') : 'confirm') {
            case 'confirm':
                $secret = $this->pendingSecret();
                $step = $secret === null ? null : Totp::match($secret, $field('code'), -1, time());
                $this->throttle->record($identifier, $request->getClientIp(), $step !== null, $user->id);
                if ($secret === null || $step === null) {
                    return $this->setup($user->id, $user->username, $this->text('invalid'), 422);
                }
                $codes = $this->factors->enroll($user->id, TotpFactor::ID, TotpFactor::state($secret, $step));
                $this->session->remove(self::PENDING_KEY);

                return $this->page($this->paragraph('done') . $this->codes($codes) . $this->back());
            case 'codes':
                $valid = $this->factors->verifyWith($user->id, TotpFactor::ID, 'enroll', $field('code'));
                $this->throttle->record($identifier, $request->getClientIp(), $valid, $user->id);
                if (!$valid) {
                    return $this->status($user->id, $this->text('invalid'), 422);
                }

                return $this->page($this->codes($this->factors->newRecoveryCodes($user->id)) . $this->back());
            case 'disable':
                $valid = $this->hasher->verify($field('password'), $user->passwordHash)
                    && $this->factors->verifyWith($user->id, TotpFactor::ID, 'remove', $field('code'));
                $this->throttle->record($identifier, $request->getClientIp(), $valid, $user->id);
                if (!$valid) {
                    return $this->status($user->id, $this->text('disable_invalid'), 422);
                }
                $this->factors->remove($user->id, TotpFactor::ID);

                return $this->page($this->paragraph('disabled') . $this->back());
            default:
                return $this->status($user->id, null, 400);
        }
    }

    /** Step-by-step setup with the QR code; the secret waits in the session until a first code proves it. */
    private function setup(int $userId, string $username, ?string $error, int $status = 200): Response
    {
        $secret = $this->pendingSecret();
        if ($secret === null) {
            $secret = Totp::newSecret();
            $this->session->set(self::PENDING_KEY, ['secret' => $secret, 'until' => time() + self::PENDING_SECONDS]);
        }

        $issuer = trim((string) ($this->site->peek('site.name') ?? '')) ?: 'Nolviko';
        try {
            $qr = QrCode::svg(Totp::uri($issuer, $username, $secret));
        } catch (Throwable) {
            $qr = '';
        }

        $body = $this->alert($error)
            . '<section class="panel panel-pad stack">' . $this->paragraph('intro')
            . '<ol class="stack">'
            . '<li>' . $this->e($this->text('step_app')) . '</li>'
            . '<li>' . $this->e($this->text('step_scan')) . '<div class="qr-figure">' . $qr . '</div>'
            . '<p class="muted">' . $this->e($this->text('manual')) . ' <code>'
            . $this->e(implode(' ', str_split($secret, 4))) . '</code></p></li>'
            . '<li>' . $this->e($this->text('step_code')) . '</li></ol>'
            . $this->form('confirm', [['code', 'code', 'one-time-code']], 'confirm')
            . '</section>';

        return $this->page($body, $status);
    }

    private function status(int $userId, ?string $error, int $status = 200): Response
    {
        $left = $this->factors->recoveryLeft($userId);
        $body = $this->alert($error)
            . '<section class="panel panel-pad stack">'
            . '<p><span class="chip chip-new">' . $this->e($this->text('on')) . '</span> '
            . $this->e($this->text('active')) . '</p>'
            . '<p>' . $this->e($this->translator->translate('nolviko.totp.codes_left', ['count' => $left])) . '</p>'
            . '</section>'
            . '<section class="panel panel-pad stack"><h2>' . $this->e($this->text('codes_heading')) . '</h2>'
            . $this->paragraph('codes_help')
            . $this->form('codes', [['code', 'code', 'one-time-code']], 'codes_submit')
            . '</section>'
            . '<section class="panel panel-pad stack"><h2>' . $this->e($this->text('disable_heading')) . '</h2>'
            . $this->paragraph('disable_help')
            . $this->form(
                'disable',
                [['password', 'password', 'current-password'], ['code', 'code', 'one-time-code']],
                'disable_submit',
                'btn-d',
            )
            . '</section>';

        return $this->page($body, $status);
    }

    /** @param list<string> $codes */
    private function codes(array $codes): string
    {
        if ($codes === []) {
            return '';
        }

        $items = implode('', array_map(
            fn(string $code): string => '<li><code>' . $this->e($code) . '</code></li>',
            $codes,
        ));

        return '<section class="panel panel-pad stack" aria-labelledby="totp-codes-title">'
            . '<h2 id="totp-codes-title">' . $this->e($this->text('codes_heading')) . '</h2>'
            . $this->paragraph('codes_save') . '<ul class="code-list">' . $items . '</ul></section>';
    }

    /** @param list<array{0: string, 1: string, 2: string}> $fields name, label key, autocomplete */
    private function form(string $action, array $fields, string $submit, string $class = ''): string
    {
        $html = '<form method="post" action="' . $this->e($this->urls->generate('nolviko.totp.setup')) . '">'
            . '<input type="hidden" name="' . $this->e(CsrfTokens::FIELD) . '" value="'
            . $this->e($this->csrf->token()) . '">'
            . '<input type="hidden" name="action" value="' . $this->e($action) . '">';
        foreach ($fields as [$name, $label, $autocomplete]) {
            $id = 'totp-' . $action . '-' . $name;
            $html .= '<p><label for="' . $id . '">' . $this->e($this->text($label)) . '</label>'
                . '<input id="' . $id . '" name="' . $name . '" type="' . ($name === 'password' ? 'password' : 'text')
                . '" required autocomplete="' . $autocomplete . '"'
                . ($name === 'code' ? ' inputmode="numeric" maxlength="64" spellcheck="false"' : '')
                . '></p>';
        }

        return $html . '<p><button type="submit"' . ($class === '' ? '' : ' class="' . $class . '"') . '>'
            . $this->e($this->text($submit)) . '</button></p></form>';
    }

    private function page(string $body, int $status = 200): Response
    {
        $html = $this->views->render('extensions/page.twig', [
            'title' => $this->text('title'),
            'body' => new SafeHtml($body),
        ]);

        return new Response($html, $status, [
            'Content-Type' => 'text/html; charset=UTF-8',
            'Cache-Control' => 'no-store, private',
            'Referrer-Policy' => 'same-origin',
        ]);
    }

    private function pendingSecret(): ?string
    {
        $pending = $this->session->get(self::PENDING_KEY);

        return is_array($pending) && is_string($pending['secret'] ?? null) && is_int($pending['until'] ?? null)
            && $pending['until'] >= time() ? $pending['secret'] : null;
    }

    private function back(): string
    {
        return '<p><a class="btn btn-s" href="' . $this->e($this->urls->generate(CoreRoutes::ACCOUNT)) . '">'
            . $this->e($this->text('back')) . '</a></p>';
    }

    private function alert(?string $error): string
    {
        return $error === null ? '' : '<p role="alert">' . $this->e($error) . '</p>';
    }

    private function paragraph(string $key): string
    {
        return '<p>' . $this->e($this->text($key)) . '</p>';
    }

    private function text(string $key): string
    {
        return $this->translator->translate('nolviko.totp.' . $key);
    }

    private function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
}
