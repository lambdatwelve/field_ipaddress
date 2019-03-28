<?php

namespace Drupal\field_ipaddress\Plugin\Field\FieldType;

use Drupal\Core\Field\FieldDefinitionInterface;
use Drupal\Core\Field\FieldStorageDefinitionInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\TypedData\DataDefinition;
use Drupal\Core\Field\FieldItemBase;
use Drupal\Core\Field\FieldItemInterface;

use Drupal\field_ipaddress\IpAddress;

/**
 * Plugin implementation of the 'ipaddress' field type.
 *
 * @FieldType(
 *   id = "ipaddress",
 *   label = @Translation("IP Address"),
 *   description = @Translation("Create and store IP addresses or ranges."),
 *   default_widget = "ipaddress_default",
 *   default_formatter = "ipaddress_default"
 * )
 */
class IpAddressField extends FieldItemBase implements FieldItemInterface {

  /**
   * {@inheritdoc}
   */
  public static function defaultStorageSettings() {
    return [] + parent::defaultStorageSettings();
  }

  /**
   * {@inheritdoc}
   */
  public static function propertyDefinitions(FieldStorageDefinitionInterface $field_definition) {
    $properties['ip_start'] = DataDefinition::create('any')
      ->setLabel(t('IP value minimum'))
      ->setDescription(t('The IP minimum value, as a binary number.'));

    $properties['ip_end'] = DataDefinition::create('any')
      ->setLabel(t('IP value maximum'))
      ->setDescription(t('The IP maximum value, as a binary number.'));

    return $properties;
  }

  /**
   * {@inheritdoc}
   */
  public static function schema(FieldStorageDefinitionInterface $field_definition) {
    return [
      'columns' => [
        // For IPv4 we store IP numbers as 4 byte binary (32 bit)
        // for IPv6 we store 16 byte binary (128 bit)
        // this follows the in_addr as used by the PHP function
        // inet_pton().
        'ip_start' => [
          'description' => 'The minimum IP address stored as a binary number.',
          'type' => 'blob',
          'size' => 'tiny',
          'mysql_type' => 'varbinary(16)',
          'not null' => TRUE,
          'binary' => TRUE,
        ],
        'ip_end' => [
          'description' => 'The maximum IP address stored as a binary number.',
          'type' => 'blob',
          'size' => 'tiny',
          'mysql_type' => 'varbinary(16)',
          'not null' => TRUE,
          'binary' => TRUE,
        ],
      ],
      'indexes' => [
        'ip_start' => ['ip_start'],
        'ip_end' => ['ip_end'],
      ],
    ];
  }

  /**
   * {@inheritdoc}
   */
  public static function generateSampleValue(FieldDefinitionInterface $field_definition) {
    // First random i IPv4 or IPv6.
    $family = (rand(0, 1) == 1);
    // IPv6 contains 16 bytes, IPv4 contains 4 bytes.
    $bytes = $family == 1 ? 16 : 4;
    // Use a built in PHP function to generate random bytes.
    $values['ip_start'] = openssl_random_pseudo_bytes($bytes);
    // Extract first part excluding last byte.
    $values['ip_end'] = substr($values['ip_start'], 0, $bytes - 1);

    $last_byte = substr($values['ip_start'], -1);

    $from_last_number = end(unpack('C', $last_byte));
    $to_last_number = rand($from_last_number, 255);
    // Add last number.
    $values['ip_end'] .= pack('C', $to_last_number);

    return $values;
  }

  /**
   * {@inheritdoc}
   */
  public function isEmpty() {
    $value = $this->get('ip_start')->getValue();
    return $value === NULL || $value == '';
  }

  /**
   * {@inheritdoc}
   */
  public static function defaultFieldSettings() {
    return [
      'allow_range'  => TRUE,
      'allow_family' => 4,
      'ip4_range'    => '',
      'ip6_range'    => '',
    ] + parent::defaultFieldSettings();
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsForm(array $form, FormStateInterface $form_state) {
    $element = [];

    $settings = $this->getSettings();

    $element['allow_family'] = [
      '#type'    => 'radios',
      '#title'   => $this->t('IP version(s) allowed'),
      '#options' => [
        IpAddress::IP_FAMILY_4   => $this->t('IPv4'),
        IpAddress::IP_FAMILY_6   => $this->t('IPv6'),
        IpAddress::IP_FAMILY_ALL => $this->t('Both IPv4 and IPv6'),
      ],
      '#description' => $this->t('Select the IP address family (or families) that are allowed.'),
      '#default_value' => $settings['allow_family'],
    ];

    $element['allow_range'] = [
      '#type'  => 'checkbox',
      '#title' => $this->t('Allow IP Range'),
      '#default_value' => $settings['allow_range'],
    ];

    $element['ip4_range'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Allowed IPv4 range.'),
      '#description' => $this->t('The range of IPv4 addresses to allow. Leave blank to allow any valid IPv4 address.'),
      '#states' => [
        'visible' => [
          [
            ':input[name="settings[allow_range]"]' => ['checked' => TRUE],
            ':input[name="settings[allow_family]"]' => ['value' => IpAddress::IP_FAMILY_4],
          ],
          [
            ':input[name="settings[allow_range]"]' => ['checked' => TRUE],
            ':input[name="settings[allow_family]"]' => ['value' => IpAddress::IP_FAMILY_ALL],
          ],
        ],
      ],
      '#default_value' => $settings['ip4_range'],
      '#element_validate' => [[$this, 'validateIpAddressElement']],
    ];

    $element['ip6_range'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Allowed IPv6 range.'),
      '#description' => $this->t('The range of IPv6 addresses to allow. Leave blank to allow any valid IPv6 address.'),
      '#states' => [
        'visible' => [
          [
            ':input[name="settings[allow_range]"]' => ['checked' => TRUE],
            ':input[name="settings[allow_family]"]' => ['value' => IpAddress::IP_FAMILY_6],
          ],
          [
            ':input[name="settings[allow_range]"]' => ['checked' => TRUE],
            ':input[name="settings[allow_family]"]' => ['value' => IpAddress::IP_FAMILY_ALL],
          ],
        ],
      ],
      '#default_value' => $settings['ip6_range'],
      '#element_validate' => [[$this, 'validateIpAddressElement']],
    ];

    return $element;
  }

  /**
   * Custom validator.
   *
   * @param array $element
   *   The element being validated.
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   *   Current form state.
   * @param array $form
   *   Current form.
   */
  public function validateIpAddressElement(array &$element, FormStateInterface $form_state, array $form) {
    $value = $form_state->getValue($element['#parents']);
    if (trim($value) == '') {
      return;
    }

    // Instantiate our IP, will throw \Exception if invalid.
    try {
      $ip_address = new IpAddress($value);
    }
    catch (\Exception $e) {
      $form_state->setError($element, t('Invalid IP or range.'));
      return;
    }

    // These fields can only accept IP ranges.
    if ($ip_address->start() == $ip_address->end()) {
      $form_state->setError($element, t('Value must be an IP range.'));
    }

    if ($element['#name'] == 'settings[ip4_range]' && $ip_address->family() != IpAddress::IP_FAMILY_4) {
      $form_state->setError($element, t('Value must be an IPv4 range.'));
    }

    if ($element['#name'] == 'settings[ip6_range]' && $ip_address->family() != IpAddress::IP_FAMILY_6) {
      $form_state->setError($element, t('Value must be an IPv6 range.'));
    }
  }

}
