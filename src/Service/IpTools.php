<?php
/**
 * IpTools provides validation and calculation for IP addresses.
 *
 * @license https://opensource.org/licenses/GPL-2.0
 * 
 * @author Antoine Musso <hashar at free dot fr>
 * @author Nick Andriopoulos <nand@lambda-twelve.com>
 */

namespace Drupal\field_ipaddress\Service;

/**
 * IpTools class is a Drupal adaptation of the MediaWiki IP class
 *
 * @see https://doc.wikimedia.org/mediawiki-core/master/php/IP_8php_source.html
 */
class IpTools {
  const RE_IP_BYTE = '(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|0?[0-9]?[0-9])';
  const RE_IP_ADD  = self::RE_IP_BYTE . '\.' . self::RE_IP_BYTE . '\.' . self::RE_IP_BYTE . '\.' . self::RE_IP_BYTE;

  // An IPv4 range is an IP address and a prefix (d1 to d32)
  const RE_IP_PREFIX = '(3[0-2]|[12]?\d)';
  const RE_IP_RANGE  = self::RE_IP_ADD . '\/' . self::RE_IP_PREFIX;

  // An IPv6 address is made up of 8 words (each x0000 to xFFFF).
  // However, the "::" abbreviation can be used on consecutive x0000 words.
  const RE_IPV6_WORD   = '([0-9A-Fa-f]{1,4})';
  const RE_IPV6_PREFIX = '(12[0-8]|1[01][0-9]|[1-9]?\d)';

  const RE_IPV6_ADD = 
    '(?:' . // starts with "::" (including "::")
         ':(?::|(?::' . self::RE_IPV6_WORD . '){1,7})' .
     '|' . // ends with "::" (except "::")
         self::RE_IPV6_WORD . '(?::' . self::RE_IPV6_WORD . '){0,6}::' .
     '|' . // contains one "::" in the middle (the ^ makes the test fail if none found)
         self::RE_IPV6_WORD . '(?::((?(-1)|:))?' . self::RE_IPV6_WORD . '){1,6}(?(-2)|^)' .
     '|' . // contains no "::"
         self::RE_IPV6_WORD . '(?::' . self::RE_IPV6_WORD . '){7}' .
     ')';

  const RE_IPV6_RANGE = self::RE_IPV6_ADD . '\/' .self::RE_IPV6_PREFIX;
  const RE_IPV6_GAP   = ':(?:0+:)*(?::(?:0+:)*)?';
  const RE_IPV6_V4_PREFIX = '0*' . self::RE_IPV6_GAP . '(?:ffff:)?';
  const IP_ADDRESS_STRING = 
    '(?:' .
         self::RE_IP_ADD . '(?:\/' . self::RE_IP_PREFIX . ')?' . // IPv4
     '|' .
         self::RE_IPV6_ADD . '(?:\/' . self::RE_IPV6_PREFIX . ')?' . // IPv6
     ')';

  public static function isIPAddress( $ip ) {
    return (bool)preg_match( '/^' . self::IP_ADDRESS_STRING . '$/', $ip );
  }

  public static function isIPv6( $ip ) {
    return (bool)preg_match( '/^' . self::RE_IPV6_ADD . '(?:\/' . self::RE_IPV6_PREFIX . ')?$/', $ip );
  }

  public static function isIPv4( $ip ) {
    return (bool)preg_match( '/^' . self::RE_IP_ADD . '(?:\/' . self::RE_IP_PREFIX . ')?$/', $ip );
  }

  public static function isValid( $ip ) {
    return ( preg_match( '/^' . self::RE_IP_ADD . '$/', $ip )
      || preg_match( '/^' . self::RE_IPV6_ADD . '$/', $ip ) );
  }

  public static function isValidBlock( $ipRange ) {
    return self::isValidRange( $ipRange );
  }

  public static function isValidRange( $ipRange ) {
    return ( preg_match( '/^' . self::RE_IPV6_RANGE . '$/', $ipRange )
      || preg_match( '/^' . self::RE_IP_RANGE . '$/', $ipRange ) );
  }

  public static function sanitizeIP( $ip ) {
    $ip = trim( $ip );
    if ( $ip === '' ) {
      return null;
    }
    /* If not an IP, just return trimmed value, since sanitizeIP() is called
    * in a number of contexts where usernames are supplied as input.
    */
    if(!self::isIPAddress($ip)) {
      return $ip;
    }
    if(self::isIPv4($ip)) {
      // Remove leading 0's from octet representation of IPv4 address
      $ip = preg_replace('!(?:^|(?<=\.))0+(?=[1-9]|0[./]|0$)!', '', $ip);
      return $ip;
    }
    
    // Remove any whitespaces, convert to upper case
    $ip = strtoupper($ip);
    // Expand zero abbreviations
    
    $abbrevPos = strpos($ip, '::');
    if ($abbrevPos !== false) {
      // We know this is valid IPv6. Find the last index of the
      // address before any CIDR number (e.g. "a:b:c::/24").
      $CIDRStart = strpos($ip, "/");
      $addressEnd = ($CIDRStart !== false)
        ? $CIDRStart - 1
        : strlen( $ip ) - 1;
      // If the '::' is at the beginning...
      if ($abbrevPos == 0) {
        $repeat = '0:';
        $extra = ( $ip == '::' ) ? '0' : ''; // for the address '::'
        $pad = 9; // 7+2 (due to '::')
      // If the '::' is at the end...
      } elseif ($abbrevPos == ($addressEnd - 1)) {
        $repeat = ':0';
        $extra = '';
        $pad = 9; // 7+2 (due to '::')
      // If the '::' is in the middle...
      } else {
        $repeat = ':0';
        $extra = ':';
        $pad = 8; // 6+2 (due to '::')
      }
      $ip = str_replace( '::',
        str_repeat($repeat, $pad - substr_count($ip, ':')) . $extra,
        $ip
      );
    }
    
    // Remove leading zeros from each bloc as needed
    $ip = preg_replace('/(^|:)0+(' . self::RE_IPV6_WORD . ')/', '$1$2', $ip);

    return $ip;
  }  

     public static function prettifyIP( $ip ) {
         $ip = self::sanitizeIP( $ip ); // normalize (removes '::')
         if ( self::isIPv6( $ip ) ) {
             // Split IP into an address and a CIDR
             if ( strpos( $ip, '/' ) !== false ) {
                 list( $ip, $cidr ) = explode( '/', $ip, 2 );
             } else {
                 list( $ip, $cidr ) = [ $ip, '' ];
             }
             // Get the largest slice of words with multiple zeros
             $offset = 0;
             $longest = $longestPos = false;
             while ( preg_match(
                 '!(?:^|:)0(?::0)+(?:$|:)!', $ip, $m, PREG_OFFSET_CAPTURE, $offset
             ) ) {
                 list( $match, $pos ) = $m[0]; // full match
                 if ( strlen( $match ) > strlen( $longest ) ) {
                     $longest = $match;
                     $longestPos = $pos;
                 }
                 $offset = ( $pos + strlen( $match ) ); // advance
             }
             if ( $longest !== false ) {
                 // Replace this portion of the string with the '::' abbreviation
                 $ip = substr_replace( $ip, '::', $longestPos, strlen( $longest ) );
             }
             // Add any CIDR back on
             if ( $cidr !== '' ) {
                 $ip = "{$ip}/{$cidr}";
             }
             // Convert to lower case to make it more readable
             $ip = strtolower( $ip );
         }
 
         return $ip;
     }
     public static function formatHex( $hex ) {
         if ( substr( $hex, 0, 3 ) == 'v6-' ) { // IPv6
             return self::hexToOctet( substr( $hex, 3 ) );
         } else { // IPv4
             return self::hexToQuad( $hex );
         }
     }  
     public static function hexToOctet( $ip_hex ) {
         // Pad hex to 32 chars (128 bits)
         $ip_hex = str_pad( strtoupper( $ip_hex ), 32, '0', STR_PAD_LEFT );
         // Separate into 8 words
         $ip_oct = substr( $ip_hex, 0, 4 );
         for ( $n = 1; $n < 8; $n++ ) {
             $ip_oct .= ':' . substr( $ip_hex, 4 * $n, 4 );
         }
         // NO leading zeroes
         $ip_oct = preg_replace( '/(^|:)0+(' . self::RE_IPV6_WORD . ')/', '$1$2', $ip_oct );
 
         return $ip_oct;
     }
 
     public static function hexToQuad( $ip_hex ) {
         // Pad hex to 8 chars (32 bits)
         $ip_hex = str_pad( strtoupper( $ip_hex ), 8, '0', STR_PAD_LEFT );
         // Separate into four quads
         $s = '';
         for ( $i = 0; $i < 4; $i++ ) {
             if ( $s !== '' ) {
                 $s .= '.';
             }
             $s .= base_convert( substr( $ip_hex, $i * 2, 2 ), 16, 10 );
         }
 
         return $s;
     }
 
     public static function isPublic( $ip ) {
         static $privateSet = null;
         if ( !$privateSet ) {
             $privateSet = new IPSet( [
                 '10.0.0.0/8', # RFC 1918 (private)
                 '172.16.0.0/12', # RFC 1918 (private)
                 '192.168.0.0/16', # RFC 1918 (private)
                 '0.0.0.0/8', # this network
                 '127.0.0.0/8', # loopback
                 'fc00::/7', # RFC 4193 (local)
                 '0:0:0:0:0:0:0:1', # loopback
                 '169.254.0.0/16', # link-local
                 'fe80::/10', # link-local
             ] );
         }
         return !$privateSet->match( $ip );
     }

public static function toHex( $ip ) {
         if ( self::isIPv6( $ip ) ) {
             $n = 'v6-' . self::IPv6ToRawHex( $ip );
         } elseif ( self::isIPv4( $ip ) ) {
             // T62035/T97897: An IP with leading 0's fails in ip2long sometimes (e.g. *.08),
             // also double/triple 0 needs to be changed to just a single 0 for ip2long.
             $ip = self::sanitizeIP( $ip );
             $n = ip2long( $ip );
             if ( $n < 0 ) {
                 $n += 2 ** 32;
                 # On 32-bit platforms (and on Windows), 2^32 does not fit into an int,
                 # so $n becomes a float. We convert it to string instead.
                 if ( is_float( $n ) ) {
                     $n = (string)$n;
                 }
             }
             if ( $n !== false ) {
                 # Floating points can handle the conversion; faster than Wikimedia\base_convert()
                 $n = strtoupper( str_pad( base_convert( $n, 10, 16 ), 8, '0', STR_PAD_LEFT ) );
             }
         } else {
             $n = false;
         }
 
         return $n;
     }
 
     private static function IPv6ToRawHex( $ip ) {
         $ip = self::sanitizeIP( $ip );
         if ( !$ip ) {
             return false;
         }
         $r_ip = '';
         foreach ( explode( ':', $ip ) as $v ) {
             $r_ip .= str_pad( $v, 4, 0, STR_PAD_LEFT );
         }
 
         return $r_ip;
     }
 
     public static function parseCIDR( $range ) {
         if ( self::isIPv6( $range ) ) {
             return self::parseCIDR6( $range );
         }
         $parts = explode( '/', $range, 2 );
         if ( count( $parts ) != 2 ) {
             return [ false, false ];
         }
         list( $network, $bits ) = $parts;
         $network = ip2long( $network );
         if ( $network !== false && is_numeric( $bits ) && $bits >= 0 && $bits <= 32 ) {
             if ( $bits == 0 ) {
                 $network = 0;
             } else {
                 $network &= ~( ( 1 << ( 32 - $bits ) ) - 1 );
             }
             # Convert to unsigned
             if ( $network < 0 ) {
                 $network += 2 ** 32;
             }
         } else {
             $network = false;
             $bits = false;
         }
 
         return [ $network, $bits ];
     }
 
     public static function parseRange( $range ) {
         // CIDR notation
         if ( strpos( $range, '/' ) !== false ) {
             if ( self::isIPv6( $range ) ) {
                 return self::parseRange6( $range );
             }
             list( $network, $bits ) = self::parseCIDR( $range );
             if ( $network === false ) {
                 $start = $end = false;
             } else {
                 $start = sprintf( '%08X', $network );
                 $end = sprintf( '%08X', $network + 2 ** ( 32 - $bits ) - 1 );
             }
         // Explicit range
         } elseif ( strpos( $range, '-' ) !== false ) {
             list( $start, $end ) = array_map( 'trim', explode( '-', $range, 2 ) );
             if ( self::isIPv6( $start ) && self::isIPv6( $end ) ) {
                 return self::parseRange6( $range );
             }
             if ( self::isIPv4( $start ) && self::isIPv4( $end ) ) {
                 $start = self::toHex( $start );
                 $end = self::toHex( $end );
                 if ( $start > $end ) {
                     $start = $end = false;
                 }
             } else {
                 $start = $end = false;
             }
         } else {
             # Single IP
             $start = $end = self::toHex( $range );
         }
         if ( $start === false || $end === false ) {
             return [ false, false ];
         } else {
             return [ $start, $end ];
         }
     }
 
     private static function parseCIDR6( $range ) {
         # Explode into <expanded IP,range>
         $parts = explode( '/', self::sanitizeIP( $range ), 2 );
         if ( count( $parts ) != 2 ) {
             return [ false, false ];
         }
         list( $network, $bits ) = $parts;
         $network = self::IPv6ToRawHex( $network );
         if ( $network !== false && is_numeric( $bits ) && $bits >= 0 && $bits <= 128 ) {
             if ( $bits == 0 ) {
                 $network = "0";
             } else {
                 # Native 32 bit functions WONT work here!!!
                 # Convert to a padded binary number
                 $network = Wikimedia\base_convert( $network, 16, 2, 128 );
                 # Truncate the last (128-$bits) bits and replace them with zeros
                 $network = str_pad( substr( $network, 0, $bits ), 128, 0, STR_PAD_RIGHT );
                 # Convert back to an integer
                 $network = Wikimedia\base_convert( $network, 2, 10 );
             }
         } else {
             $network = false;
             $bits = false;
         }
 
         return [ $network, (int)$bits ];
     }
 
     private static function parseRange6( $range ) {
         # Expand any IPv6 IP
         $range = self::sanitizeIP( $range );
         // CIDR notation...
         if ( strpos( $range, '/' ) !== false ) {
             list( $network, $bits ) = self::parseCIDR6( $range );
             if ( $network === false ) {
                 $start = $end = false;
             } else {
                 $start = Wikimedia\base_convert( $network, 10, 16, 32, false );
                 # Turn network to binary (again)
                 $end = Wikimedia\base_convert( $network, 10, 2, 128 );
                 # Truncate the last (128-$bits) bits and replace them with ones
                 $end = str_pad( substr( $end, 0, $bits ), 128, 1, STR_PAD_RIGHT );
                 # Convert to hex
                 $end = Wikimedia\base_convert( $end, 2, 16, 32, false );
                 # see toHex() comment
                 $start = "v6-$start";
                 $end = "v6-$end";
             }
         // Explicit range notation...
         } elseif ( strpos( $range, '-' ) !== false ) {
             list( $start, $end ) = array_map( 'trim', explode( '-', $range, 2 ) );
             $start = self::toHex( $start );
             $end = self::toHex( $end );
             if ( $start > $end ) {
                 $start = $end = false;
             }
         } else {
             # Single IP
             $start = $end = self::toHex( $range );
         }
         if ( $start === false || $end === false ) {
             return [ false, false ];
         } else {
             return [ $start, $end ];
         }
     }
 
     public static function isInRange( $addr, $range ) {
         $hexIP = self::toHex( $addr );
         list( $start, $end ) = self::parseRange( $range );
 
         return ( strcmp( $hexIP, $start ) >= 0 &&
             strcmp( $hexIP, $end ) <= 0 );
     }
 
     public static function isInRanges( $ip, $ranges ) {
         foreach ( $ranges as $range ) {
             if ( self::isInRange( $ip, $range ) ) {
                 return true;
             }
         }
         return false;
     }
 
     public static function canonicalize( $addr ) {
         // remove zone info (T37738)
         $addr = preg_replace( '/\%.*/', '', $addr );
 
         if ( self::isValid( $addr ) ) {
             return $addr;
         }
         // Turn mapped addresses from ::ce:ffff:1.2.3.4 to 1.2.3.4
         if ( strpos( $addr, ':' ) !== false && strpos( $addr, '.' ) !== false ) {
             $addr = substr( $addr, strrpos( $addr, ':' ) + 1 );
             if ( self::isIPv4( $addr ) ) {
                 return $addr;
             }
         }
         // IPv6 loopback address
         $m = [];
         if ( preg_match( '/^0*' . self::RE_IPV6_GAP . '1$/', $addr, $m ) ) {
             return '127.0.0.1';
         }
         // IPv4-mapped and IPv4-compatible IPv6 addresses
         if ( preg_match( '/^' . self::RE_IPV6_V4_PREFIX . '(' . self::RE_IP_ADD . ')$/i', $addr, $m ) ) {
             return $m[1];
         }
         if ( preg_match( '/^' . self::RE_IPV6_V4_PREFIX . self::RE_IPV6_WORD .
             ':' . self::RE_IPV6_WORD . '$/i', $addr, $m )
         ) {
             return long2ip( ( hexdec( $m[1] ) << 16 ) + hexdec( $m[2] ) );
         }
 
         return null; // give up
     }
 
     public static function sanitizeRange( $range ) {
         list( /*...*/, $bits ) = self::parseCIDR( $range );
         list( $start, /*...*/ ) = self::parseRange( $range );
         $start = self::formatHex( $start );
         if ( $bits === false ) {
             return $start; // wasn't actually a range
         }
 
         return "$start/$bits";
     }
 
     public static function getSubnet( $ip ) {
         $matches = [];
         $subnet = false;
         if ( self::isIPv6( $ip ) ) {
             $parts = self::parseRange( "$ip/64" );
             $subnet = $parts[0];
         } elseif ( preg_match( '/^(\d+\.\d+\.\d+)\.\d+$/', $ip, $matches ) ) {
             // IPv4
             $subnet = $matches[1];
         }
         return $subnet;
     }

}