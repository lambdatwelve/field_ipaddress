<?php

namespace Drupal\field_ipaddress\Plugin\Field\FieldFormatter;

use Drupal\Core\Field\FieldItemListInterface;
use Drupal\Core\Field\FormatterBase;
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
  public function viewElements(FieldItemListInterface $items, $langcode) {
    $elements = [];

    foreach ($items as $delta => $item) {
      $value = $item->getValue();

      if (!empty($value['ip_start'])) {
        $text = inet_ntop($value['ip_start']);

        if ($value['ip_start'] != $value['ip_end']) {
          $text .= '-' . inet_ntop($value['ip_end']);
        }
      }

      $elements[$delta] = [
        '#plain_text' => $text,
      ];
    }

    return $elements;
  }

}
