<?php

declare(strict_types=1);

namespace Drupal\device_token;

use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityChangedInterface;
use Drupal\user\EntityOwnerInterface;

/**
 * Provides an interface defining a device token entity type.
 */
interface DeviceTokenInterface extends ContentEntityInterface, EntityOwnerInterface, EntityChangedInterface {

}
