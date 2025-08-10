<?php

namespace Drupal\device_token\Plugin\rest\resource;

use Drupal\user\Entity\User;
use Psr\Log\LoggerInterface;
use Drupal\rest\Plugin\ResourceBase;
use Drupal\rest\ResourceResponse;
use Drupal\consumers\Entity\Consumer;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Drupal\encrypt\EncryptServiceInterface;
use Drupal\encrypt\Entity\EncryptionProfile;

/**
 * Provides a REST endpoint to generate a device token and certificate.
 *
 * @RestResource(
 *   id = "device_token_cert_resource",
 *   label = @Translation("Device Token Resource"),
 *   uri_paths = {
 *     "create" = "/api/device-token"
 *   }
 * 
 * )
 */

class DeviceTokenCertResource extends ResourceBase {

  protected EntityTypeManagerInterface $entityTypeManager;
  protected RequestStack $requestStack;
  protected EncryptServiceInterface $encryptService;

  public function __construct(
    array $configuration,
    $plugin_id,
    $plugin_definition,
    array $serializer_formats,
    LoggerInterface $logger,
    EntityTypeManagerInterface $entityTypeManager,
    RequestStack $requestStack,
    EncryptServiceInterface $encryptService
  ) {
    parent::__construct($configuration, $plugin_id, $plugin_definition, $serializer_formats, $logger);
    $this->entityTypeManager = $entityTypeManager;
    $this->requestStack = $requestStack;
    $this->encryptService = $encryptService;
  }

  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->getParameter('serializer.formats'),
      $container->get('logger.factory')->get('device_token_cert_resource'),
      $container->get('entity_type.manager'),
      $container->get('request_stack'),
      $container->get('encryption')
    );
  }

  public function post($data = []) {
    $request = $this->requestStack->getCurrentRequest();
    $content = $request->getContent();
    $data = json_decode($content, TRUE);

    if (!is_array($data) || empty($data['device_token'])) {
      throw new BadRequestHttpException('Invalid or missing "device_token" field.');
    }

    $device_token_input = $data['device_token'];
    $device_token_storage = $this->entityTypeManager->getStorage('device_token');

    $signature = $request->headers->get('X-Signature');
    if (empty($signature)) {
      throw new BadRequestHttpException('Missing HMAC signature header.');
    }

    // Retrieve and decrypt HMAC secret from config.
    $config = \Drupal::config('device_token.settings');
    $hmac_secret_encoded = $config->get('secret_key');

    if (empty($hmac_secret_encoded)) {
      throw new \RuntimeException('HMAC secret is not configured.');
    }

    $encryption_profile = $this->entityTypeManager
      ->getStorage('encryption_profile')
      ->load('hmac_encryption');

    if (!$encryption_profile) {
      throw new \RuntimeException('Encryption profile "hmac_encryption" not found.');
    }

    $hmac_secret = $this->encryptService->decrypt(base64_decode($hmac_secret_encoded), $encryption_profile);

    $expected_signature = hash_hmac('sha256', $device_token_input, $hmac_secret);
    if (!hash_equals($expected_signature, $signature)) {
      throw new BadRequestHttpException('Invalid HMAC signature.');
    }

    // Check for existing device token.
    $device_token_ids = $device_token_storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('device_token', $device_token_input)
      ->range(0, 1)
      ->execute();

    // Generate hmac_key for entity storage.
    $entity_hmac_key = hash_hmac('sha256', $content, $hmac_secret);

    if (!empty($device_token_ids)) {
      $deviceToken = $device_token_storage->load(reset($device_token_ids));
      $user = $deviceToken->getOwner();

      $cert_info = $this->generateClientCertificate($device_token_input);

      $deviceToken->set('fingerprint', $cert_info['fingerprint']);
      $deviceToken->set('expires', \Drupal::time()->getCurrentTime() + 1800);
      // $deviceToken->set('hmac_key', $entity_hmac_key);
      $deviceToken->save();

      [$client_id, $client_secret] = $this->createOAuthClient($deviceToken, $user);

      return new ResourceResponse([
        'cert' => $cert_info['cert'],
        'key' => $cert_info['key'],
        'fingerprint' => $cert_info['fingerprint'],
        'hmac_key' => $entity_hmac_key,
        'oauth_client_id' => $client_id,
        'oauth_client_secret' => $client_secret,
        'grant_type' => 'client_credentials',
        'token_endpoint' => '/oauth/token',
        'expires_in' => 3600,
      ], 200);
    }

    // Create new user and device token.
    $username = 'ssl_tester_' . substr(hash('sha256', $device_token_input . microtime(true)), 0, 8);
    $email = $username . '@example.com';

    $user = User::create([
      'name' => $username,
      'mail' => $email,
      'status' => 1,
    ]);
    $user->addRole('ssl_tester');
    $user->save();

    $cert_info = $this->generateClientCertificate($username);

    $deviceToken = $device_token_storage->create([
      'type' => 'device_token',
      'uid' => $user->id(),
      'label' => $device_token_input,
      'fingerprint' => $cert_info['fingerprint'],
      'expires' => \Drupal::time()->getCurrentTime() + 1800,
      'device_token' => $device_token_input,
      'status' => 1,
      'hmac_key' => $entity_hmac_key,
    ]);
    $deviceToken->save();

    [$client_id, $client_secret] = $this->createOAuthClient($deviceToken, $user);

    return new ResourceResponse([
      'cert' => $cert_info['cert'],
      'key' => $cert_info['key'],
      'fingerprint' => $cert_info['fingerprint'],
      'hmac_key' => $entity_hmac_key,
      'oauth_client_id' => $client_id,
      'oauth_client_secret' => $client_secret,
      'grant_type' => 'client_credentials',
      'token_endpoint' => '/oauth/token',
      'expires_in' => 3600,
    ], 201);
  }

  protected function generateClientCertificate(string $common_name): array {
    $config = \Drupal::config('device_token.settings');
    $ca_cert = $config->get('ca_certificate');
    $ca_key = $config->get('ca_private_key');

    if (empty($ca_cert) || empty($ca_key)) {
      throw new \RuntimeException('CA certificate or private key not configured.');
    }

    $priv_key_res = openssl_pkey_new(['private_key_bits' => 2048]);
    openssl_pkey_export($priv_key_res, $client_key);

    $dn = ['commonName' => $common_name];
    $csr = openssl_csr_new($dn, $priv_key_res);

    $ca_cert_res = openssl_x509_read($ca_cert);
    $ca_key_res = openssl_pkey_get_private($ca_key);

    $client_cert_res = openssl_csr_sign($csr, $ca_cert_res, $ca_key_res, 365, ['digest_alg' => 'sha256']);
    openssl_x509_export($client_cert_res, $client_cert_out);
    ddl($client_cert_out);
    ddl($client_key);

    return [
      'cert' => $client_cert_out,
      'key' => $client_key,
      'fingerprint' => strtoupper(openssl_x509_fingerprint($client_cert_res, 'sha256')),
    ];
  }

  protected function createOAuthClient($deviceToken, User $user): array {
    $client_id = 'test_client_' . $deviceToken->id();
    $existing = $this->entityTypeManager->getStorage('consumer')->loadByProperties(['client_id' => $client_id]);

    $plain_secret = base64_encode(\Drupal::service('key.repository')->getKey('simple_oauth_key')->getKeyValue());
    $hashed_secret = password_hash($plain_secret, PASSWORD_DEFAULT);

    if ($existing) {
      $consumer = reset($existing);
      $consumer->set('secret', $hashed_secret);
      $consumer->get('secret')->pre_hashed = true;
      $consumer->save();
    } else {
      $scope = current($this->entityTypeManager->getStorage('oauth2_scope')->loadByProperties(['id' => 'get_token']));
      $consumer_data = [
        'label' => 'OAuth Client for Device Token ' . $deviceToken->id(),
        'client_id' => $client_id,
        'secret' => $hashed_secret,
        'user_id' => $user->id(),
        'grant_types' => ['client_credentials'],
        'confidential' => true,
        'third_party' => false,
        'description' => 'Generated OAuth client for device token.',
        'scopes' => $scope ? [$scope->id()] : [],
      ];
      $consumer = Consumer::create($consumer_data);
      $consumer->get('secret')->pre_hashed = true;
      $consumer->save();
    }

    return [$client_id, $plain_secret];
  }

}
