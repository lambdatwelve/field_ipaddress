<?php

namespace Drupal\field_ipaddress\Plugin\Field\FieldWidget;

use Drupal\Core\Field\FieldItemListInterface;
use Drupal\Core\Field\WidgetBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * Base class for the 'ipaddress_*' widgets.
 */
class IpAddressWidgetBase extends WidgetBase {
  /**
   * {@inheritdoc}
   */
  public function formElement(FieldItemListInterface $items, $delta, array $element, array &$form, FormStateInterface $form_state) {

    $element['settings'] = $this->fieldDefinition->getSettings();
    kint($element['settings']);

    $element = array(
      'value' => $element + array(
        '#type' => 'textfield'
      )
    );

    $element['#element_validate'] = array(array(get_class($this), 'validateIpAddressElement'));

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
  public static function validateIpAddressElement(&$element, FormStateInterface $form_state, $form) {
    if (trim($element['value']['#value']) === '') { 
      return;
    }

    // Get field settings.
    $settings = $element['settings'];

    // Get helper service.
    $iptool   = \Drupal::service('field_ipaddress.service.iptools');

    // Get rid of spaces
    $value = $iptool->sanitizeIP($element['value']['#value']);

    // Check if this is an IP range
    if($iptool->isValidRange($value)) {
      // Split to bounds
      $form_state->setError($element, 'Cant handle ranges yet.');
      return;
    }

    // Check if this is a simple IP address 
    if($iptool->isValid($value)) {
      // Check address family, make sure it matches settings.
      if($settings['allow_family']===4 && !$iptool->isIPv4($value)) {
        $form_state->setError($element, t('Only single IPv4 addresses are allowed.'));
      }

      if($settings['allow_family']===6 && !$iptool->ipIPv6($value)) {
        $form_state->setError($element, t('Only single IPv6 addresses are allowed.')); 
      }

      // Check if we need to validate IP range
      if($settings['ip_range']!='') {
        // Check if IP is within range
        if(!$iptool->isInRange($value, $settings['ip_range'])) {
          $form_state->setError($element, t('IP must be within the range @range', array('@range'=>$settings['ip_range'])));
        }
      }

      return;
    }

    $form_state->setError($element, t('Invalid IP format.'));
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
