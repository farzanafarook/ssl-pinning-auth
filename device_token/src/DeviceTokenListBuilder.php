<?php

declare(strict_types=1);

namespace Drupal\device_token;

use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\EntityListBuilder;

/**
 * Provides a list controller for the device token entity type.
 */
final class DeviceTokenListBuilder extends EntityListBuilder {

  /**
   * {@inheritdoc}
   */
  public function buildHeader(): array {
    $header['id'] = $this->t('ID');
    $header['label'] = $this->t('Label');
    $header['status'] = $this->t('Status');
    $header['uid'] = $this->t('Author');
    $header['created'] = $this->t('Created');
    $header['changed'] = $this->t('Updated');
    return $header + parent::buildHeader();
  }

  /**
   * {@inheritdoc}
   */
  public function buildRow(EntityInterface $entity): array {
    /** @var \Drupal\device_token\DeviceTokenInterface $entity */
    $row['id'] = $entity->id();
    $row['label'] = $entity->toLink($entity->label(), 'canonical');
    $row['status'] = $entity->get('status')->value ? $this->t('Enabled') : $this->t('Disabled');

    $author_entity = $entity->get('uid')->entity;
    $username_options = ['label' => 'hidden'];

    if ($author_entity) {
      $username_options['settings'] = ['link' => $author_entity->isAuthenticated()];
      $row['uid']['data'] = $entity->get('uid')->view($username_options);
    }
    else {
      $row['uid']['data'] = [
        '#markup' => $this->t('Anonymous'),
      ];
    }

    $row['created']['data'] = $entity->get('created')->view(['label' => 'hidden']);
    $row['changed']['data'] = $entity->get('changed')->view(['label' => 'hidden']);

    return $row + parent::buildRow($entity);
  }

}
