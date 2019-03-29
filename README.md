# INTRODUCTION

The field_ipaddress module allows the creation of fields that contain IP infor-
mation. It is compatible (aka performs validation) for both IPv4 and IPv6, both
single IPs and IP ranges (simple "dash" ranges like `1.1.1.1-2.2.2.2` and CIDR
ranges like `192.168.0.0/24`, in both IPv4 **and IPv6**). 

It also provides per field instance settings as to the allowed IPs in the field,
such as:
  * IP family (only allow IPv4 or IPv6 or both)
  * Allow IP ranges
  * Limit IPs to a specific range

# REQUIREMENTS

* To be able to use the IPv6 features, your PHP needs to be complied with
support for it (on by default). 
* Drupal Core (no external dependencies)

# INSTALLATION

 * Install as you would normally install a contributed Drupal module. 
   Visit [Drupal.org](https://www.drupal.org/docs/8/extending-drupal-8/installing-drupal-8-modules) for further information.

# CONFIGURATION

* Add the field to any fieldable entity.
* Use the field instance settings to configure allowed values.
* There are no menus or settings other than these.

# FAQ

**Q**: Does this module translate IPv4 to IPv6 for mixes mode addresses?
**A**: Nope, IP families are treated separately.

# MAINTAINERS

Current maintainers:
 * Nick Andriopoulos (hexblot) - https://www.drupal.org/u/hexblot

This project has been sponsored by:
 * LAMBDA TWELVE
 Specialized in consulting and planning of web solutions, [Lambda Twelve](https://www.lambda-twelve.com) offers
 development, hosting, and anything in between for your project.
  
