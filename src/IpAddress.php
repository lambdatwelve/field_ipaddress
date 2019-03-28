<?php
/**
 * IpTools provides validation and calculation for IP addresses.
 *
 * @license https://opensource.org/licenses/GPL-2.0
 * @author Nick Andriopoulos <nand@lambda-twelve.com>
 */

namespace Drupal\field_ipaddress;

/**
 * IpTools class
 */
class IpAddress {
  const IP_FAMILY_4     = 4;
  const IP_FAMILY_6     = 6;
  const IP_FAMILY_ALL   = 10;

  const IP_RANGE_SIMPLE = 2;
  const IP_RANGE_CIDR   = 3;
  const IP_RANGE_NONE   = 0;

  protected $family = null;
  protected $type   = null;
  protected $start  = null;
  protected $end    = null;
  protected $raw    = null;

  /* Define simple getters for our properties */  
  public function family() {
    return $this->family;
  }

  public function type() {
    return $this->type;
  }

  public function start() {
    return $this->start;
  }

  public function end() {
    return $this->end;
  }

  // On construction, parse the given value
  public function __construct($value) {
    $this->raw = $value;
    $result = $this->parse($value);

    if($result === FALSE) {
      $this->family = null;
      $this->type   = null;
      $this->start  = null;
      $this->end    = null;
      throw new \Exception('Invalid value.');
    }
  }

  public function inRange($min, $max) {
    if(
         !$this->isIpAddress($min) 
      || !$this->isIpAddress($max)
    ) {
      throw new \Exception('Invalid value.'); 
    }

    // IPs in different families are by default not within range.
    if(
         $this->getFamily($min) != $this->family 
      || $this->getFamily($max) != $this->family
    ) {
     return FALSE;
    }

    if($this->family == self::IP_FAMILY_4) {
      return $this->inRange4($min,$max);
    } else {
      return $this->inRange6($min,$max);
    }
  }

  // Simple checks for an IP address
  private function isIPAddress($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP);
  }

  private function isIPv6($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 );
  }

  private function isIPv4($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
  }

  // Find if the IP family is IPv4 or IPv6
  private function getFamily($ip) {
    if($this->isIPv4($ip)) {
      return self::IP_FAMILY_4;
    } 
    return self::IP_FAMILY_6;
  }

  // Find if the value given is an IP, IP range, or other
  private function parse($value) {
    $value = trim(str_replace(' ','', $value));

    // Check if this is a simple range
    if(strpos($value, '-')!== FALSE) {
      // Break its parts apart
      list($start, $end) = explode('-', $value, 2);
      
      if(
        // Check that both ends are valid IPs
        !$this->isIpAddress($start) || !$this->isIPAddress($end) 
        // Check that both are in the same family
        || ($this->isIPv6($start) && !$this->isIPv6($end))  
        || ($this->isIPv4($start) && !$this->isIPv4($end))
        ) {
        // Return false on failure
        return FALSE;
      }

      // Simple is ... simple, assign the bounds
      $this->start  = $start;
      $this->end    = $end;
      $this->family = $this->getFamily($start);
      $this->type   = self::IP_RANGE_SIMPLE;

    } // Check if we have a CIDR address
    elseif(strpos($value, '/')!==FALSE) {

      // Break its parts apart
      list($ip,$prefix) = explode('/', $value, 2);

      if(
        !$this->isIPAddress($ip)
        || !is_numeric($prefix)
        || $prefix <= 0
      ) {
        return FALSE;
      }

      $this->family = $this->getFamily($ip);

      // Check that the prefix is not larger than the bits available in the address.
      if(
        ($this->family == self::IP_FAMILY_4 && $prefix > 32)
        || ($this->family == self::IP_FAMILY_6 && $prefix > 128 )
      ) {
        return FALSE;
      }

      $this->type = self::IP_RANGE_CIDR;

      // Calculate CIDR address bounds
      if($this->family == self::IP_FAMILY_4) {
        $this->calcCIDR4($ip, $prefix);
      } else {
        $this->calcCIDR6($ip, $prefix);
      }

    } // Finally, check if this is a simple IP
    elseif($this->isIPAddress($value)) {
      $this->type   = self::IP_RANGE_NONE;
      $this->family = $this->getFamily($value);
      $this->start  = $value;
      $this->end    = $value;
      
    } // All has failed, this is something else
    else {
      return FALSE;    
    }
  }

  /*
   * Calculates the IP range for an IPv4 CIDR formatted range.
   *
   * @see https://stackoverflow.com/questions/15961557/calculate-ip-range-using-php-and-cidr#answer-55229198
   */
  private function calcCIDR4($ip, $prefix) {
    $this->start = long2ip((ip2long($ip)) & ((-1 << (32 - (int)$prefix))));
    $this->end   = long2ip((ip2long($this->start)) + pow(2, (32 - (int)$prefix)) - 1);
  }

  /*
   * Calculates the IP range for an IPv6 CIDR formatted range.
   *
   * @see https://stackoverflow.com/questions/10085266/php5-calculate-ipv6-range-from-cidr-prefix#answer-10086404
   */
  private function calcCIDR6($ip, $prefix) {
    $start_bin = $this->packIP6($ip);
    $this->start = inet_ntop($start_bin);

    // Convert the binary string to a string with hexadecimal characters
    $start_hex = reset(unpack('H*', $start_bin));

    // Calculate flexible bits
    $flexbits = 128 - $prefix;

    $end_hex = $start_hex;
    $pos = 31;
    while ($flexbits > 0) {
      // Get the character at this position
      $orig = substr($end_hex, $pos, 1);

      // Convert it to an integer
      $origval = hexdec($orig);

      // OR it with (2^flexbits)-1, with flexbits limited to 4 at a time
      $newval = $origval | (pow(2, min(4, $flexbits)) - 1);

      // Convert it back to a hexadecimal character
      $new = dechex($newval);

      // And put that character back in the string
      $end_hex = substr_replace($end_hex, $new, $pos, 1);

      // We processed one nibble, move to previous position
      $flexbits -= 4;
      $pos -= 1;
    }

    $end_bin = pack('H*', $end_hex);
    // And create an IPv6 address from the binary string
    $this->end = inet_ntop($end_bin);
  }

  private function packIP4($ip) {
    return inet_pton(preg_replace('/\b0+(?=\d)/', '', $ip));
  }

  private function packIP6($ip) {
    return inet_pton($ip);
  }

  /*
   * Checks if the current IPv4 is within a given min and max IP
   *
   * @see https://stackoverflow.com/questions/18336908/php-check-if-ip-address-is-in-a-range-of-ip-addresses/18336909#answer-18336909
   */
  private function inRange4($min,$max) {
    $min_long = ip2long($min);
    $max_long = ip2long($max);

    if($this->type == self::IP_RANGE_NONE) {
      $start_long = $end_long = ip2long($this->start);  
    } else {
      $start_long = ip2long($this->start); 
      $end_long   = ip2long($this->end);
    }
    
    return (
      ($start_long >= $min_long && $start_long <= $max_long)
      && ( $end_long >= $min_long && $end_long <= $max_long)
    );
  }

  /*
   * Checks if the current IPv6 is within a given min and max IP
   */
  private function inRange6($min,$max) {
    $min_bin = inet_pton($min);
    $max_bin = inet_pton($max);

    if($this->type == self::IP_RANGE_NONE) {
      $start_bin = $end_bin = inet_pton($this->start);
    } else {
      $start_bin = inet_pton($this->start);
      $end_bin   = inet_pton($this->end);
    }

    return (
      ($start_bin >= $min_bin && $start_bin <= $max_bin)
      && ( $end_bin >= $min_bin && $end_bin <= $max_bin)
    );
  }


}
