<?php

namespace Drupal\field_ipaddress\Plugin\Field\FieldFormatter;

use Drupal\Core\Field\FieldItemListInterface;
use Drupal\Core\Field\FormatterBase;
use Drupal\Core\Field\FieldDefinitionInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Plugin\ContainerFactoryPluginInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Plugin implementation of the 'Default' formatter for 'datetime' fields.
 *
 * @FieldFormatter(
 *   id = "ipaddress_default",
 *   label = @Translation("Default"),
 *   field_types = {
 *     "ipaddress"
 *   }
 * )
 */
class IpAddressDefaultFormatter extends FormatterBase implements ContainerFactoryPluginInterface {
  /**
   * Constructs a new DateTimeDefaultFormatter.
   *
   * @param string $plugin_id
   *   The plugin_id for the formatter.
   * @param mixed $plugin_definition
   *   The plugin implementation definition.
   * @param \Drupal\Core\Field\FieldDefinitionInterface $field_definition
   *   The definition of the field to which the formatter is associated.
   * @param array $settings
   *   The formatter settings.
   * @param string $label
   *   The formatter label display setting.
   * @param string $view_mode
   *   The view mode.
   * @param array $third_party_settings
   */
  public function __construct($plugin_id, $plugin_definition, FieldDefinitionInterface $field_definition, array $settings, $label, $view_mode, array $third_party_settings) {
    parent::__construct($plugin_id, $plugin_definition, $field_definition, $settings, $label, $view_mode, $third_party_settings);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $plugin_id,
      $plugin_definition,
      $configuration['field_definition'],
      $configuration['settings'],
      $configuration['label'],
      $configuration['view_mode'],
      $configuration['third_party_settings']
    );
  }

  /**
   * {@inheritdoc}
   */
  public static function defaultSettings() {
    return array(
      'allow_range'  => TRUE,
      'allow_family' => array('ipv4','ipv6'),
      'ip_min'       => '',
      'ip_max'       => ''
    ) + parent::defaultSettings();
  }

  /**
   * {@inheritdoc}
   */
  public function viewElements(FieldItemListInterface $items, $langcode) {
    $elements = array();

    foreach ($items as $delta => $item) {
      if (($value = $item->getValue()) && !empty($value['ip_from'])) {
        $text = inet_ntop($value['ip_from']);
        if ($value['ip_to'] != $value['ip_from']) {
          $text .= ' - ' . inet_ntop($value['ip_to']);
        }

        $elements[$delta] = array(
          '#plain_text' => $text,
        );
      }
    }

    

    return $elements;

  }

  /**
   * {@inheritdoc}
   */
  public function settingsForm(array $form, FormStateInterface $form_state) {
    $form = parent::settingsForm($form, $form_state);

    $form['allow_range'] = array(
      '#type'  => 'checkbox',
      '#title' => $this->t('Allow IP Range'),
      '#default_value' => $this->getSetting('allow_range')
    );

    $form['allowed_versions'] = array(
      '#type'    => 'checkboxes',
      '#title'   => $this->t('IP version(s) allowed'),
      '#options' => array(
        'ipv4' => 'IPv4', 
        'ipv6' => 'IPv6',
      ),
      '#default_value' => $this->getSetting('allow_family')
    );

    $form['minimum'] = array(
      '#type' => 'textfield',
      '#title' => $this->t('Allowed IP range.'),
      '#description' => $this->t('Range must match IP version otherwise validation will always fail.')
    );



    return $form;
  }

  /**
   * {@inheritdoc}
   */
  public function settingsSummary() {
    //$summary = parent::settingsSummary();
    $summary = array();
    $settings = $this->getSettings();
    $summary[] = $settings['allow_range']?$this->t('Ranges allowed'):$this->t('Ranges NOT allowed');
    $summary[] = $this->t('Allowed IP versions: ').implode($settings['allow_family']);
    $summary[] = $this->t('IP Range: ').$settings['ip_min'].' - '.$settings['ip_max'];
    return $summary;
  }

}
