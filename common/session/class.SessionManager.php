<?php

/**
 * SPDX-FileCopyrightText: 2013-2026 Open Assessment Technologies S.A.
 * Copyright (C) 2013-2026 (original work) Open Assessment Technologies S.A.
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TAO-Commercial-License
 */

use oat\oatbox\user\BasicUser;
use Zend\ServiceManager\ServiceLocatorAwareInterface;
use oat\oatbox\service\ServiceManager;

/**
 * Represents a Session on Generis.
 *
 * @access private
 * @author Joel Bout, <joel@taotesting.com>
 * @package generis

 */
abstract class common_session_SessionManager
{
    public const PHPSESSION_SESSION_KEY = 'common_session_Session';

    private static $session = null;

    /**
     * Retrurns the current session
     *
     * @throws common_exception_Error
     * @return common_session_Session
     */
    public static function getSession()
    {
        if (is_null(self::$session)) {
            $session = self::createAccessTokenSession();
            if ($session) {
                self::$session = $session;
            } elseif (PHPSession::singleton()->hasAttribute(self::PHPSESSION_SESSION_KEY)) {
                $session = PHPSession::singleton()->getAttribute(self::PHPSESSION_SESSION_KEY);
                if (! $session instanceof common_session_Session) {
                    throw new common_exception_Error('Non session stored in php-session');
                }
                self::$session = $session;
            } else {
                self::$session = new common_session_AnonymousSession();
            }
        }
        if (self::$session instanceof ServiceLocatorAwareInterface) {
            self::$session->setServiceLocator(ServiceManager::getServiceManager());
        }
        return self::$session;
    }

    /**
     * Starts a new session and stores it in the session if stateful
     *
     * @param common_session_Session $session
     * @return boolean
     */
    public static function startSession(common_session_Session $session)
    {

        self::$session = $session;
        // do not start session in cli mode (testcase script)
        if (PHP_SAPI != 'cli') {
            if ($session instanceof common_session_StatefulSession) {
                // start session if not yet started
                if (session_id() === '') {
                    session_name(GENERIS_SESSION_NAME);
                    session_start();
                } else {
                    // prevent session fixation.
                    session_regenerate_id();
                }

                PHPSession::singleton()->setAttribute(self::PHPSESSION_SESSION_KEY, $session);
            }
        }
        return true;
    }

    /**
     * Ends the session by replacing it with an anonymous session
     *
     * @return boolean
     */
    public static function endSession()
    {

        // clean session data.
        if (session_id() != '') {
            session_destroy();
        }

        return self::startSession(new common_session_AnonymousSession());
    }

    /**
     * Is the current session anonymous or associated to a user?
     *
     * @return boolean
     */
    public static function isAnonymous()
    {
        return is_null(self::getSession()->getUserUri());
    }

    public static function extractAccessTokenFromRequest(): string
    {
        $authorizationHeader = explode(' ', $_SERVER['HTTP_AUTHORIZATION'] ?? '', 2);
        return array_pop($authorizationHeader) ?: $_GET['jwt'] ?? '';
    }

    public static function parseAccessToken(string $accessToken): ?array
    {
        /** @noinspection PhpUnusedLocalVariableInspection */
        @[$_, $payload] = explode('.', $accessToken);
        $rawToken = base64_decode(strtr($payload ?? '', '-_', '+/'));
        return json_decode($rawToken, true);
    }

    public static function buildUserIdentityString(string $userId, string $role = ''): string
    {
        return sprintf('%s%s%s', $role, $role ? '#' : '', $userId);
    }

    private static function createAccessTokenSession(): ?common_session_Session
    {
        $token = self::parseAccessToken(self::extractAccessTokenFromRequest());
        if (
            empty($token['user']['login'])
            || !is_string($token['user']['login'])
            || !preg_match(
                '/^(?:(?<role>[^#]*#[^#]*)#)?(?<userId>.*)$/',
                $token['user']['login'],
                $matches
            )
        ) {
            return null;
        }

        $role = $matches['role'] ?? '';
        return new common_session_BasicSession(
            new BasicUser(
                $role,
                $role ? [$role] : [],
                $matches['userId'],
            )
        );
    }
}
