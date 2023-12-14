# o365_Security_Audit

This script has python engage with CLI to grab user data (currently failed and successful logins) and then audits this data per user looking for flags (currently more than 3 IP addresses used in 3 hours, or more than 2 states in the IP addresses within 8 hours), eventually it will do something with these flags and will get deployed on some cadence.
