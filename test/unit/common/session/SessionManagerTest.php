<?php

/**
 * SPDX-FileCopyrightText: 2026 Open Assessment Technologies S.A.
 * Copyright (C) 2026 (original work) Open Assessment Technologies S.A.
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TAO-Commercial-License
 */

declare(strict_types=1);

namespace oat\generis\test\unit\common\session;

use common_session_AnonymousSession as AnonumousSession;
use common_session_SessionManager as SessionManager;
use DateTimeImmutable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\JwtFacade;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use oat\generis\model\GenerisRdf;
use oat\generis\model\user\UserRdf;
use oat\oatbox\user\BasicUser;
use PHPUnit\Framework\TestCase;

class SessionManagerTest extends TestCase
{
    public static function dataProvider(): array
    {
        return [
            'No role' => ['user_id_1', '', ['login' => 'user_id_1']],
            'TAO 3.x role' => [
                'user_id_2',
                GenerisRdf::INSTANCE_ROLE_GENERIS,
                ['login' => GenerisRdf::INSTANCE_ROLE_GENERIS . '#user_id_2'],
            ],
        ];
    }

    /**
     * @dataProvider dataProvider
     */
    public function testParseAccessToken(string $userId, string $role, array $expected): void
    {
        $this->assertSame(
            $expected,
            SessionManager::parseAccessToken($this->generateAccessToken($userId, $role))['user'] ?? []
        );
    }

    /**
     * @runInSeparateProcess
     */
    public function testExtractAccessTokenFromRequest(): void
    {
        $token = $this->generateAccessToken('test_user_id');
        $this->setAccessToken($token);
        $this->assertSame($token, SessionManager::extractAccessTokenFromRequest());
    }

    /**
     * @runInSeparateProcess
     */
    public function testExtractAccessTokenFromRequestQueryParameters(): void
    {
        $token = $this->generateAccessToken('test_user_id');
        $this->setAccessTokenToQueryParameters($token);
        $this->assertSame($token, SessionManager::extractAccessTokenFromRequest());
    }

    /**
     * @runInSeparateProcess
     * @dataProvider dataProvider
     */
    public function testGetAccessTokenBasedSession(string $userId, string $role): void
    {
        $token = $this->generateAccessToken($userId, $role);
        $this->setAccessToken($token);
        $user = SessionManager::getSession()->getUser();
        $this->assertInstanceOf(BasicUser::class, $user);
        $this->assertSame([$userId], $user->getPropertyValues(UserRdf::PROPERTY_LOGIN));
        $this->assertSame($role, $user->getIdentifier());
        $this->assertSame($role ? [$role] : [], $user->getRoles());
    }

    /**
     * @runInSeparateProcess
     * @dataProvider dataProvider
     */
    public function testGetAccessTokenBasedSessionFromQueryParameters(string $userId, string $role): void
    {
        $token = $this->generateAccessToken($userId, $role);
        $this->setAccessTokenToQueryParameters($token);
        $user = SessionManager::getSession()->getUser();
        $this->assertInstanceOf(BasicUser::class, $user);
        $this->assertSame([$userId], $user->getPropertyValues(UserRdf::PROPERTY_LOGIN));
        $this->assertSame($role, $user->getIdentifier());
        $this->assertSame($role ? [$role] : [], $user->getRoles());
    }

    /**
     * @runInSeparateProcess
     */
    public function testGetCookieBasedSession(): void
    {
        $this->assertInstanceOf(AnonumousSession::class, SessionManager::getSession());
    }

    private function setAccessToken(string $token): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = "Bearer $token";
    }

    private function setAccessTokenToQueryParameters(string $token): void
    {
        $_GET['jwt'] = $token;
    }

    private function generateAccessToken(string $userId = '', string $role = ''): string
    {
        $userIdentity = $userId ? SessionManager::buildUserIdentityString($userId, $role) : null;
        $key = InMemory::base64Encoded(bin2hex(random_bytes(32)));
        return (new JwtFacade())->issue(
            new Sha256(),
            $key,
            static function (
                Builder $builder,
                DateTimeImmutable $issuedAt,
            ) use ($userIdentity): Builder {
                $builder = $builder
                    ->issuedBy('https://backoffice.ngs.test')
                    ->expiresAt($issuedAt->modify('+1 minute'));
                return $userIdentity ? $builder->withClaim('user', ['login' => $userIdentity]) : $builder;
            }
        )->toString();
    }
}
