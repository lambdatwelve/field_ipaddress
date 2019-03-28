<?php

namespace Drupal\field_ipaddress\Plugin\Field\FieldWidget;

use Drupal\Core\Field\FieldItemListInterface;
use Drupal\Core\Field\WidgetBase;
use Drupal\Core\Form\FormStateInterface;

use Drupal\field_ipaddress\IpAddress;

/**
 * Base class for the 'ipaddress_*' widgets.
 */
class IpAddressWidgetBase extends WidgetBase {
  /**
   * {@inheritdoc}
   */
  public function formElement(FieldItemListInterface $items, $delta, array $element, array &$form, FormStateInterface $form_state) {

    $element = array(
      'value' => $element + array(
        '#type' => 'textfield'
      )
    );

    $element['#element_validate'] = array(array($this, 'validateIpAddressElement'));

    /*
    if (($value = $items[$delta]->getValue()) && !empty($value['ip_from'])) {
      $element['value']['#default_value'] = inet_ntop($value['ip_from']);
      if ($value['ip_to'] != $value['ip_from']) {
        $element['value']['#default_value'] .= ' - ' . inet_ntop($value['ip_to']);
      }
    }*/

    return $element;
  }

  /**
   * Custom validator
   *
   * @param $element
   * @param \Drupal\Core\Form\FormStateInterface $form_state
   * @param $form
   */
  public  function validateIpAddressElement(&$element, FormStateInterface $form_state, $form) {
    $settings = $this->fieldDefinition->getSettings();
    kint($settings);
    $value = trim($element['value']['#value']);
    if ($value === '') { 
      return;
    }

    // Instantiate our IP, will throw \Exception if invalid.
    try {
      $ip_address = new IpAddress($value);
    } catch(\Exception $e) {
      // Make error messages a bit more relevant.
      if($settings['allow_range']) {
        $form_state->setError($element, t('Invalid IP or range.'));  
      } else {
        $form_state->setError($element, t('Invalid IP.'));  
      }
    }

    if(!$settings['allow_range'] && $ip_address->start() != $ip_address->end())) {
      $form_state->setError($element, t('Ranges not allowed, single IP only.'));  
    }

    if($settings['allow_family'] != $ip_address::IP_FAMILY_BOTH && $settings['allow_family']!=$ip_address->family()) {
      if($settings['allow_family'] == $ip_address::IP_FAMILY_IPV4) {
        $form_state->setError($element, t('Only IPv4 addresses allowed.'));   
      } else {
        $form_state->setError($element, t('Only IPv6 addresses allowed.'));   
      }
    }

    kint($ip_address);
    
    
    

    

    $form_state->setError($element, t('You shall not pass.'));
  }


  /**
   * {@inheritdoc}
   */
  public function massageFormValues(array $values, array $form, FormStateInterface $form_state) {
    // Convert to storage format
    foreach ($values as &$item) {
      if (!empty($value = trim($item['value']))) {
          // Get rid of spaces
          $value = str_replace(' ', '', $value);
          // If a range, extract the parts
          $ip_parts = explode('-', $value);
          $item['ip_from'] = filter_var($ip_parts[0], FILTER_VALIDATE_IP) ? inet_pton($ip_parts[0]) : '';

          if (isset($ip_parts[1])) {
            $item['ip_to'] = filter_var($ip_parts[1], FILTER_VALIDATE_IP) ? inet_pton($ip_parts[1]) : '';
          }
          else {
            $item['ip_to'] = $item['ip_from'];
          }
          // IPv6 addresses as in_addr are 16 bytes, check if this is true
          $item['ipv6'] = (strlen($item['ip_from']) == 16) ? 1 : 0;
      }
    }
    return $values;
  }

  /**
   * {@inheritdoc}
   */
  public static function defaultSettings() {
    $settings = parent::defaultSettings();

    $settings['ipv4_span'] = 65536; // 2^16
    $settings['ipv6_span'] = 16777216; // 2^24

    return $settings;
  }

  /**
   * {@inheritdoc}
   */
  function settingsForm(array $form, FormStateInterface $form_state) {
    $element = parent::settingsForm($form, $form_state);

    $element['ipv4_span'] = array(
      '#type' => 'textfield',
      '#title' => t('Maximum span for IPv4 addresses'),
      '#default_value' => $this->getSetting('ipv4_span'),
    );

    $element['ipv6_span'] = array(
      '#type' => 'textfield',
      '#title' => t('Maximum span for IPv6 addresses'),
      '#default_value' => $this->getSetting('ipv6_span'),
    );

    return $element;
  }

  /**
   * {@inheritdoc}
   */
  public function settingsSummary() {
    $summary = array();

    $summary[] = t('Spans: @ipv4 (IPv4) / @ipv6 (IPv6)', array('@ipv4' => $this->getSetting('ipv4_span'), '@ipv6' => $this->getSetting('ipv6_span')));

    return $summary;
  }

}
