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

    $value = $items[$delta]->getValue();
    if(!empty($value['ip_from'])) {
      $element['value']['#default_value'] = inet_ntop($value['ip_from']);
    }

    if($value['ip_from']!=$value['ip_to']) {
      $element['value']['#default_value'] .= '-'.inet_ntop($value['ip_to']);
    }

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

    if(!$settings['allow_range'] && $ip_address->start() != $ip_address->end()) {
      $form_state->setError($element, t('Ranges not allowed, single IP only.'));  
    }

    if($settings['allow_family'] != IpAddress::IP_FAMILY_ALL && $settings['allow_family']!=$ip_address->family()) {
      if($settings['allow_family'] == IpAddress::IP_FAMILY_4) {
        $form_state->setError($element, t('Only IPv4 addresses allowed.'));   
      } else {
        $form_state->setError($element, t('Only IPv6 addresses allowed.'));   
      }
    }

    if($settings['ip4_range'] && $ip_address->family() == IpAddress::IP_FAMILY_4) {
      // No validation for $ip4_range here, it should have already been done on field settings form.
      $range = new IpAddress($settings['ip4_range']);
      if(!$ip_address->inRange($range->start(), $range->end())) {
        $form_state->setError($element, t('IP must be within the range @min-@max', array('@min'=>$range->start(), '@max'=>$range->end())));
      }
    }

    if($settings['ip6_range'] && $ip_address->family() == IpAddress::IP_FAMILY_6) {
      // No validation for $ip6_range here, it should have already been done on field settings form.
      $range = new IpAddress($settings['ip6_range']);
      if(!$ip_address->inRange($range->start(), $range->end())) {
        $form_state->setError($element, t('IP must be within the range @min-@max', array('@min'=>$range->start(), '@max'=>$range->end())));
      }
    }
  }


  /**
   * {@inheritdoc}
   */
  public function massageFormValues(array $values, array $form, FormStateInterface $form_state) {
    // Convert to storage format
    foreach ($values as &$item) {
      if (!empty($value = trim($item['value']))) {
          $value = new IpAddress($value);

          $item['ip_from'] = inet_pton($value->start());
          $item['ip_to']   = inet_pton($value->end());
          $item['ipv6']    = (int) $value->family() == IpAddress::IP_FAMILY_6;
      }
    }
    return $values;
  }

}
