<?php

/**
 * SPDX-FileCopyrightText: 2026 Open Assessment Technologies S.A.
 * Copyright (C) 2026 (original work) Open Assessment Technologies S.A.
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TAO-Commercial-License
 */

declare(strict_types=1);

namespace oat\oatbox\user;

use oat\generis\model\user\UserRdf;

class BasicUser implements User
{
    public function __construct(
        private readonly string $identifier,
        private readonly array $roles,
        private readonly string $login
    ) {
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function getPropertyValues($property): array
    {
        if ($property === UserRdf::PROPERTY_LOGIN) {
            return [$this->login];
        }

        return [];
    }
}
