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

namespace oat\generis\test\unit\core\data\event;

use core_kernel_classes_Class;
use oat\generis\model\data\event\ClassPropertyDeletedEvent;
use oat\generis\test\TestCase;

class ClassPropertyDeletedEventTest extends TestCase
{
    public function testGetters()
    {
        $classMock = $this->createMock(core_kernel_classes_Class::class);
        $subject = new ClassPropertyDeletedEvent($classMock, ['propertyUri' => 'uri']);
        $this->assertEquals($classMock, $subject->getClass());
        $this->assertArrayHasKey('propertyUri', $subject->getProperties());
        $this->assertEquals(ClassPropertyDeletedEvent::class, $subject->getName());
    }
}
