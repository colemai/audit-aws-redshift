audit Redshift
============================
This stack will monitor Redshift and alert on things CloudCoreo developers think are violations of best practices


## Description
This repo is designed to work with CloudCoreo. It will monitor Redshift against best practices for you and send a report to the email address designated by the config.yaml AUDIT&#95;AWS&#95;REDSHIFT&#95;ALERT&#95;RECIPIENT value


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-redshift/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

### `AUDIT_AWS_REDSHIFT_RECIPIENT_2`:
  * description: Enter the email address(es) that will receive notifications for objects with no owner tag (Optional, only if owner tag is enabled).


## Required variables with default

### `AUDIT_AWS_REDSHIFT_ALERT_LIST`:
  * description: Which alerts would you like to check for? (Default is all Redshift alerts)
  * default: redshift-publicly-accessible, redshift-encrypted, redshift-no-version-upgrade, redshift-no-require-ssl, redshift-no-user-logging, redshift-snapshot-retention

### `AUDIT_AWS_REDSHIFT_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is false.
  * default: false

### `AUDIT_AWS_REDSHIFT_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is change.
  * default: change

### `AUDIT_AWS_REDSHIFT_REGIONS`:
  * description: List of AWS regions to check. Default is us-east-1,us-west-1,us-west-2.
  * default: us-east-1, us-east-2, us-west-1, us-west-2, eu-west-1

### `AUDIT_AWS_REDSHIFT_FULL_JSON_REPORT`:
  * description: Would you like to send the full JSON report? Options - notify / nothing. Default is notify.
  * default: nothing

### `AUDIT_AWS_REDSHIFT_ROLLUP_REPORT`:
  * description: Would you like to send a Summary ELB report? Options - notify / nothing. Default is no / nothing.
  * default: nothing

### `AUDIT_AWS_REDSHIFT_OWNERS_HTML_REPORT`:
  * description: notify or nothing
  * default: notify


## Optional variables with default

### `AUDIT_AWS_REDSHIFT_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of owner of the ELB object. (Optional)
  * default: NOT_A_TAG


## Optional variables with no default

### `AUDIT_AWS_REDSHIFT_ALERT_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.

## Tags
1. Audit
1. Best Practices
1. Alert
1. Redshift

## Categories
1. Audit



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-redshift/master/images/diagram.png "diagram")


## Icon


