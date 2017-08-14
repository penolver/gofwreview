# README #

## firewall review tool, written in Go ##

designed to be a quick review of a rule-base (not config review, just rule-base)

a bit (VERY) dirty at the moment

WARNING: I really wouldn't use this, its unfinished, but if i ever get time will make it actually do some useful stuff, it can pull apart a SRX rulebase and dump into CSV and will have a stab at reviewing a rulebase, but unused objects partially works.

#### features ####

* parse rule-base into generic format
* dump as CSV
* Analysis, in progress:
- Find objects that are not used in any rules (WARNING: still struggling with global / apply groups, manually verify output for those)
- Rules that can potentially be merged as they share the same source and destination
- Rules that contain Any
- Rules that Don’t have logging enabled
- Rules that contain insecure services: telnet etc
- Rules that contain large number of services (e.g. not as tight as they should be)
- Bi-directional rules that likely created in error (e.g. not appreciating a firewall is stateful)
- test for overlapping or shadowed rules..

#### currently supports devices ####

* SRX (using "show configuration | display set" output)
