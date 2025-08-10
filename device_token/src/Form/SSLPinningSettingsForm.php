<?php

namespace Drupal\device_token\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * Defines the SSL Pinning settings form.
 */
class SSLPinningSettingsForm extends ConfigFormBase {

  /**
   * {@inheritdoc}
   */
  public function getFormId(): string {
    return 'ssl_pinning_settings_form';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames(): array {
    return ['device_token.settings'];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state): array {
    $config = $this->config('device_token.settings');

    $form['ca_certificate'] = [
      '#type' => 'textarea',
      '#title' => $this->t('CA Certificate (PEM format)'),
      '#description' => $this->t('Paste the CA certificate used to sign client certs.'),
      '#default_value' => $config->get('ca_certificate') ?: '',
      '#rows' => 10,
    ];

    $form['ca_private_key'] = [
      '#type' => 'textarea',
      '#title' => $this->t('CA Private Key (PEM format)'),
      '#description' => $this->t('Paste the CA private key used to sign client certs.'),
      '#default_value' => $config->get('ca_private_key') ?: '',
      '#rows' => 10,
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state): void {
    $this->config('device_token.settings')
      ->set('ca_certificate', $form_state->getValue('ca_certificate'))
      ->set('ca_private_key', $form_state->getValue('ca_private_key'))
      ->save();

    parent::submitForm($form, $form_state);
  }

}
