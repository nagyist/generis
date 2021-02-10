<?php

/**
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; under version 2
 * of the License (non-upgradable).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Copyright (c) 2021 (original work) Open Assessment Technologies SA;
 */

declare(strict_types=1);

namespace oat\generis\model\data\event;

use core_kernel_classes_Class;
use oat\oatbox\event\Event;

class ClassDeletedEvent implements Event
{
    /** @var core_kernel_classes_Class */
    private $class;

    public function __construct(core_kernel_classes_Class $class)
    {
        $this->class = $class;
    }

    public function getName(): string
    {
        return self::class;
    }

    public function getClass(): core_kernel_classes_Class
    {
        return $this->class;
    }
}
