<?php

namespace Drupal\field_ipaddress\Plugin\Field\FieldType;

use Drupal\Core\Field\FieldDefinitionInterface;
use Drupal\Core\Field\FieldStorageDefinitionInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\TypedData\DataDefinition;
use Drupal\Core\Field\FieldItemBase;
use Drupal\Core\Field\FieldItemInterface;

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
class IpAddress extends FieldItemBase implements FieldItemInterface {

  /**
   * {@inheritdoc}
   */
  public static function defaultStorageSettings() {
    return array() + parent::defaultStorageSettings();
  }

  /**
   * {@inheritdoc}
   */
  public static function propertyDefinitions(FieldStorageDefinitionInterface $field_definition) {
    $properties['ipv6'] = DataDefinition::create('boolean')
      ->setLabel(t('Type of IP number i IPv6'))
      ->setRequired(FALSE);

    $properties['ip_from'] = DataDefinition::create('any')
      ->setLabel(t('IP value minimum'))
      ->setDescription(t('The IP minimum value, as a binary number.'));

    $properties['ip_to'] = DataDefinition::create('any')
      ->setLabel(t('IP value maximum'))
      ->setDescription(t('The IP maximum value, as a binary number.'));

    return $properties;
  }

  /**
   * {@inheritdoc}
   */
  public static function schema(FieldStorageDefinitionInterface $field_definition) {
    return array(
      'columns' => array(
        'ipv6' => array(
          'description' => 'If this is a IPv6 type address',
          'type' => 'int',
          'size' => 'tiny',
          'default' => 0,
          'not null' => TRUE,
        ),
        // For IPv4 we store IP numbers as 4 byte binary (32 bit)
        // for IPv6 we store 16 byte binary (128 bit)
        // this follows the in_addr as used by the PHP function
        // inet_pton().
        'ip_from' => array(
          'description' => 'The minimum IP address stored as a binary number.',
          'type' => 'blob',
          'size' => 'tiny',
          'mysql_type' => 'varbinary(16)',
          'not null' => TRUE,
          'binary' => TRUE
        ),
        'ip_to' => array(
          'description' => 'The maximum IP address stored as a binary number.',
          'type' => 'blob',
          'size' => 'tiny',
          'mysql_type' => 'varbinary(16)',
          'not null' => TRUE,
          'binary' => TRUE
        ),
      ),
      'indexes' => array(
        'ipv6' => array('ipv6'),
        'ip_from' => array('ip_from'),
        'ip_to' => array('ip_to')
      ),
    );
  }



  /**
   * {@inheritdoc}
   */
  public static function generateSampleValue(FieldDefinitionInterface $field_definition) {
    // First random i IPv4 or IPv6
    $values['ipv6'] = (rand(0,1) == 1);
    // IPv6 contains 16 bytes, IPv4 contains 4 bytes
    $bytes = $values['ipv6'] == 1 ? 16 : 4;
    // Use a built in PHP function to generate random bytes
    $values['ip_from'] = openssl_random_pseudo_bytes($bytes);
    // Extract first part excluding last byte
    $values['ip_to'] = substr($values['ip_from'], 0, $bytes - 1);

    $last_byte = substr($values['ip_from'], -1);

    $from_last_number = end(unpack('C', $last_byte));
    $to_last_number = rand($from_last_number, 255);
    // Add last number
    $values['ip_to'] .= pack('C', $to_last_number);

    return $values;
  }

  /**
   * {@inheritdoc}
   */
  public function isEmpty() {
    $value = $this->get('ip_from')->getValue();
    return $value === NULL || $value === '';
  }

  /**
   * {@inheritdoc}
   */
  public static function defaultFieldSettings() {
    return array(
      'allow_range'  => TRUE,
      'allow_family' => 4,
      'ip_range'     => '',
    ) + parent::defaultFieldSettings();
  }

  /**
   * {@inheritdoc}
   */
  public function fieldSettingsForm(array $form, FormStateInterface $form_state) {
    $element = array();

    $settings = $this->getSettings();
    \Drupal::messenger()->addStatus(print_r($settings,1));

    $element['ip_specific'] = array(
      '#type' => 'details',
      '#title' => $this->t('IP Specific settings'),
      '#description' => $this->t('These settings are IP validation specific to this field instance.'),
      '#open' => TRUE
    );

    $element['ip_specific']['allow_family'] = array(
      '#type'    => 'radios',
      '#title'   => $this->t('IP version(s) allowed'),
      '#options' => array(
        4 => $this->t('IPv4'), 
        6 => $this->t('IPv6'),
        1 => $this->t('Both IPv4 and IPv6'),
      ),
      '#description' => $this->t('Select the IP address family (or families) that are allowed.'),
      '#default_value' => $settings['allow_family']
    );

    $element['ip_specific']['allow_range'] = array(
      '#type'  => 'checkbox',
      '#title' => $this->t('Allow IP Range'),
      '#default_value' => $settings['allow_range']
    );    

    $element['ip_specific']['ip_range'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Allowed IP range.'),
      '#description' => $this->t('Range must match IP version otherwise validation will always fail.<br/>Leave blank to allow any valid IP.'),
      '#states' => array(
        'visible' => array(
          ':input[name="settings[ip_specific][allow_range]"]' => array('checked' => TRUE)
        )
      ),
      '#default_value' => $settings['ip_range'],
      //'#element_validate' => array(array($this, 'validateRange'))
    );



    return $element;

  }

  public function validateRange($element, FormStateInterface $form_state) {
    $submitted_value = $form_state->getValue($element['#parents']);
   //$form_state->setError($element, '<pre>'.print_r($submitted_value,1).'</pre>');
  }


}
