<?php

namespace Drupal\custom_auth\Authentication\Provider;

use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\user\UserInterface;
use Symfony\Component\HttpFoundation\Request;
use Drupal\device_token\Entity\DeviceToken;

/**
 * SSL Pinning Authentication provider.
 */
class SSLPinningAuth implements AuthenticationProviderInterface {

  /**
   * The user entity storage.
   *
   * @var \Drupal\Core\Entity\EntityStorageInterface
   */
  protected $userStorage;

  /**
   * The device_token entity storage.
   *
   * @var \Drupal\Core\Entity\EntityStorageInterface
   */
  protected $deviceTokenStorage;

  /**
   * Constructs a new SSLPinningAuth object.
   */
  public function __construct(EntityTypeManagerInterface $entityTypeManager) {
    $this->userStorage = $entityTypeManager->getStorage('user');
    $this->deviceTokenStorage = $entityTypeManager->getStorage('device_token');
  }

  /**
   * {@inheritdoc}
   */
  public function applies(Request $request) {
    $contentType = $request->headers->get('Content-Type');
    return $contentType && str_contains($contentType, 'application/vnd.api+json');
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request): ?UserInterface {
    // Get client certificate from server.
    $cert_pem = $_SERVER['SSL_CLIENT_CERT'] ?? NULL;

    // Convert PEM to OpenSSL cert resource.
    $cert_res = openssl_x509_read($cert_pem);

    // Compute fingerprint in SHA-256 format (colon-separated, uppercase).
    $fingerprint = openssl_x509_fingerprint($cert_res, 'sha256');
    $normalized_fp = strtoupper($fingerprint);

    // Get device token from custom header.
    $device_token_value = $request->headers->get('X-Device-Token');

    // Match fingerprint and token in the device_token storage.
    $ids = $this->deviceTokenStorage
      ->getQuery()
      ->accessCheck(FALSE)
      ->condition('device_token', $device_token_value)
      ->condition('fingerprint', $normalized_fp)
      ->condition('expires', \Drupal::time()->getCurrentTime(), '>')
      ->execute();

    // Load user from matched device token.
    /** @var \Drupal\device_token\Entity\DeviceToken $deviceToken */
    $deviceToken = DeviceToken::load(reset($ids));
    $user = $deviceToken->get('uid')->entity ?? NULL;

    if ($user instanceof UserInterface) {
      \Drupal::logger('custom_auth')->notice('Authentication success for user ID @uid via SSL pinning.', [
        '@uid' => $user->id(),
      ]);
      return $user;
    }

    return NULL;
  }

  /**
   * {@inheritdoc}
   */
  public function getProviderId() {
    return 'ssl_pinning';
  }

  /**
   * {@inheritdoc}
   */
  public function getAuthenticationTokens(Request $request) {
    return [];
  }

}
