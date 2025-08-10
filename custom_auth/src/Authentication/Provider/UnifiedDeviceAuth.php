<?php

namespace Drupal\custom_auth\Authentication\Provider;

use Symfony\Component\HttpFoundation\Request;
use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\user\UserInterface;
use Psr\Log\LoggerInterface;
use Drupal\device_token\Entity\DeviceToken;

/**
 * Unified Device Authentication provider.
 * Supports OAuth Bearer, HMAC header, and SSL Pinning.
 */
class UnifiedDeviceAuth implements AuthenticationProviderInterface {

  protected EntityTypeManagerInterface $entityTypeManager;
  protected LoggerInterface $logger;

  public function __construct(EntityTypeManagerInterface $entityTypeManager, LoggerInterface $logger) {
    $this->entityTypeManager = $entityTypeManager;
    $this->logger = $logger;
  }

  /**
   * {@inheritdoc}
   */
  public function applies(Request $request): bool {
    $auth = $request->headers->get('Authorization');
    return (
      $request->headers->has('X-Device-Token') &&
      $request->headers->has('X-Device-HMAC-Key') &&
      $auth && str_starts_with($auth, 'Bearer ') &&
      isset($_SERVER['SSL_CLIENT_CERT'])
    );
  }


  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request): ?UserInterface {
    $auth = $request->headers->get('Authorization');
    $hmacKey = $request->headers->get('X-Device-HMAC-Key');
    $deviceTokenValue = $request->headers->get('X-Device-Token');
    $certPem = $_SERVER['SSL_CLIENT_CERT'] ?? NULL;

    if (!$auth || !$hmacKey || !$deviceTokenValue || !$certPem) {
      $this->logger->warning('Missing one or more required headers or certificate.');
      return NULL;
    }

    // Parse OAuth token
    if (!str_starts_with($auth, 'Bearer ')) {
      return NULL;
    }

    $token = trim(str_replace('Bearer', '', $auth));
    $certRes = openssl_x509_read($certPem);
    $fingerprint = strtoupper(openssl_x509_fingerprint($certRes, 'sha256'));

    // Find matching device_token
    $query = $this->entityTypeManager->getStorage('device_token')->getQuery();
    $ids = $query
      ->accessCheck(FALSE)
      ->condition('device_token', $deviceTokenValue)
      ->condition('hmac_key', $hmacKey)
      ->condition('oauth_access_token', $token)
      ->condition('fingerprint', $fingerprint)
      ->condition('expires', \Drupal::time()->getCurrentTime(), '>')
      ->execute();

    if (!empty($ids)) {
      /** @var \Drupal\device_token\Entity\DeviceToken $deviceToken */
      $deviceToken = DeviceToken::load(reset($ids));
      $user = $deviceToken->getOwner();

      if ($user instanceof UserInterface && $user->isActive()) {
        $this->logger->notice('Unified authentication succeeded for user @uid', ['@uid' => $user->id()]);
        return $user;
      }
    }

    $this->logger->warning('Unified authentication failed.');
    return NULL;
  }


  protected function authenticateOAuth(Request $request): ?UserInterface {
    $auth = $request->headers->get('Authorization');
    if (!$auth || !str_starts_with($auth, 'Bearer ')) {
      return NULL;
    }

    $token = trim(str_replace('Bearer', '', $auth));
    $ids = $this->entityTypeManager->getStorage('device_token')
      ->getQuery()
      ->accessCheck(FALSE)
      ->condition('oauth_access_token', $token)
      ->execute();

    if (!empty($ids)) {
      $deviceToken = DeviceToken::load(reset($ids));
      return $deviceToken?->getOwner();
    }

    return NULL;
  }

  protected function authenticateHmac(Request $request): ?UserInterface {
    $providedKey = $request->headers->get('X-Device-HMAC-Key');
    if (empty($providedKey)) {
      return NULL;
    }

    $deviceTokens = $this->entityTypeManager->getStorage('device_token')->loadByProperties([
      'hmac_key' => $providedKey,
    ]);

    if (!empty($deviceTokens)) {
      $deviceToken = reset($deviceTokens);
      $user = $deviceToken->getOwner();
      return $user->isActive() ? $user : NULL;
    }

    return NULL;
  }

  protected function authenticateSslPinning(Request $request): ?UserInterface {
    $certPem = $_SERVER['SSL_CLIENT_CERT'] ?? NULL;
    if (!$certPem) {
      return NULL;
    }

    $certRes = openssl_x509_read($certPem);
    $fingerprint = strtoupper(openssl_x509_fingerprint($certRes, 'sha256'));
    $deviceTokenValue = $request->headers->get('X-Device-Token');

    if (!$deviceTokenValue) {
      return NULL;
    }

    $ids = $this->entityTypeManager->getStorage('device_token')
      ->getQuery()
      ->accessCheck(FALSE)
      ->condition('device_token', $deviceTokenValue)
      ->condition('fingerprint', $fingerprint)
      ->condition('expires', \Drupal::time()->getCurrentTime(), '>')
      ->execute();

    if (!empty($ids)) {
      $deviceToken = DeviceToken::load(reset($ids));
      return $deviceToken?->getOwner();
    }

    return NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function getProviderId(): string {
    return 'unified_device_auth';
  }

  /**
   * {@inheritdoc}
   */
  public function getAuthenticationTokens(Request $request): array {
    return [
      'authorization' => $request->headers->get('Authorization'),
      'hmac_key' => $request->headers->get('X-Device-HMAC-Key'),
      'ssl_token' => $request->headers->get('X-Device-Token'),
    ];
  }

}
