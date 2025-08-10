<?php

namespace Drupal\custom_auth\Authentication\Provider;

use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\key\KeyRepositoryInterface;
use Drupal\user\UserInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * HMAC Authentication provider.
 */
class HmacAuth implements AuthenticationProviderInterface {

  protected $configFactory;
  protected $keyRepository;
  protected $entityTypeManager;
  protected $logger;

  public function __construct(
    ConfigFactoryInterface $configFactory,
    KeyRepositoryInterface $keyRepository,
    EntityTypeManagerInterface $entityTypeManager,
    LoggerInterface $logger
  ) {
    $this->configFactory = $configFactory;
    $this->keyRepository = $keyRepository;
    $this->entityTypeManager = $entityTypeManager;
    $this->logger = $logger;
  }

  /**
   * {@inheritdoc}
   */
  public function applies(Request $request) {
    return $request->headers->has('X-Device-HMAC-Key');
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request): ?UserInterface {
    $providedKey = $request->headers->get('X-Device-HMAC-Key');

    if (empty($providedKey)) {
      $this->logger->warning('Missing HMAC key in header.');
      return NULL;
    }

    $device_tokens = $this->entityTypeManager->getStorage('device_token')->loadByProperties([
      'hmac_key' => $providedKey,
    ]);

    if (empty($device_tokens)) {
      $this->logger->warning('Invalid HMAC key.');
      return NULL;
    }

    /** @var \Drupal\device_token\Entity\DeviceToken $device_token */
    $device_token = reset($device_tokens);
    $user = $device_token->getOwner();

    if (!$user || !$user->isActive()) {
      $this->logger->warning('User is blocked or invalid for HMAC key.');
      return NULL;
    }

    $this->logger->notice('Authenticated via HMAC key for user @uid', ['@uid' => $user->id()]);
    return $user;
  }

  /**
   * {@inheritdoc}
   */
  public function getProviderId() {
    return 'hmac_auth';
  }

  /**
   * {@inheritdoc}
   */
  public function getAuthenticationTokens(Request $request) {
    return [
      'hmac_key' => $request->headers->get('X-Device-HMAC-Key'),
    ];
  }
}
