<?php

namespace Drupal\custom_auth\Authentication\Provider;

use Symfony\Component\HttpFoundation\Request;
use Drupal\user\UserInterface;
use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;

class OAuthDeviceAuth implements AuthenticationProviderInterface {

  protected EntityTypeManagerInterface $entityTypeManager;

  public function __construct(EntityTypeManagerInterface $entityTypeManager) {
    $this->entityTypeManager = $entityTypeManager;
  }

  /**
   * {@inheritdoc}
   */
  public function applies(Request $request) {
    // Only apply if Authorization header exists and starts with "Bearer"
    $authorization = $request->headers->get('Authorization');
    return $authorization && str_starts_with($authorization, 'Bearer ');
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request) {
    $authorization = $request->headers->get('Authorization');
    $token = trim(str_replace('Bearer', '', $authorization));

    // Query device_token entity with matching oauth access token
    $device_token_ids = \Drupal::entityQuery('device_token')
      ->accessCheck(FALSE)
      ->condition('oauth_access_token', $token)
      ->execute();

    if (!empty($device_token_ids)) {
      $device_token = $this->entityTypeManager->getStorage('device_token')->load(reset($device_token_ids));
      return $device_token?->getOwner();
    }

    return NULL;
  }

}
