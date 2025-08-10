<?php

namespace Drupal\device_token\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\encrypt\EncryptServiceInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;

class HmacAuthSettingsForm extends ConfigFormBase {

  protected EncryptServiceInterface $encryptService;
  protected EntityTypeManagerInterface $entityTypeManager;

  public function __construct($config_factory, EncryptServiceInterface $encrypt_service, EntityTypeManagerInterface $entity_type_manager) {
    parent::__construct($config_factory);
    $this->encryptService = $encrypt_service;
    $this->entityTypeManager = $entity_type_manager;
  }

  public static function create(ContainerInterface $container): static {
    return new static(
      $container->get('config.factory'),
      $container->get('encryption'),
      $container->get('entity_type.manager')
    );
  }

  public function getFormId(): string {
    return 'hmac_auth_settings_form';
  }

  protected function getEditableConfigNames(): array {
    return ['device_token.settings'];
  }

  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config('device_token.settings');

    $users = $this->entityTypeManager->getStorage('user')->loadByProperties(['status' => 1]);
    $options = [];
    foreach ($users as $user) {
      $options[$user->id()] = $user->getAccountName();
    }

    $form['allowed_user'] = [
      '#type' => 'select',
      '#title' => $this->t('Allowed User'),
      '#options' => $options,
      '#default_value' => $config->get('allowed_user'),
      '#required' => TRUE,
    ];

    $form['secret_key'] = [
      '#type' => 'password',
      '#title' => $this->t('Secret Key'),
      '#description' => $this->t('Enter a new HMAC secret to encrypt and store. Leave blank to keep existing.'),
    ];

    $form['time_window'] = [
      '#type' => 'number',
      '#title' => $this->t('Time Window (seconds)'),
      '#description' => $this->t('The acceptable time window for HMAC requests to prevent replay attacks.'),
      '#default_value' => $config->get('time_window') ?: 300,
      '#required' => TRUE,
      '#min' => 60,
      '#max' => 3600,
      '#field_suffix' => ' seconds',
    ];

    return parent::buildForm($form, $form_state);
  }

  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $config = $this->config('device_token.settings');
    $config->set('allowed_user', $form_state->getValue('allowed_user'));
    $config->set('time_window', $form_state->getValue('time_window'));

    $secret = $form_state->getValue('secret_key');
    if ($secret) {
      $encryption_profile = $this->entityTypeManager
        ->getStorage('encryption_profile')
        ->load('hmac_encryption');

      if ($encryption_profile) {
        $encrypted = $this->encryptService->encrypt($secret, $encryption_profile);
        $config->set('secret_key', base64_encode($encrypted));
      }
      else {
        $this->messenger()->addError($this->t('Encryption profile "hmac_encryption" not found. Cannot store HMAC secret.'));
      }
    }

    $config->save();
    parent::submitForm($form, $form_state);
  }

}
