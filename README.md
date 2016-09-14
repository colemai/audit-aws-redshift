audit Redshift
============================
This stack will monitor Redshift and alert on things CloudCoreo developers think are violations of best practices


## Description

This repo is designed to work with CloudCoreo. It will monitor Redshift against best practices for you and send a report to the email address designated by the config.yaml AUDIT_AWS_REDSHIFT_ALERT_RECIPIENT value

## Variables Requiring Your Input

### `AUDIT_AWS_REDSHIFT_ALERT_RECIPIENT`:
  * description: email recipient for notification

## Variables Required but Defaulted

### `AUDIT_AWS_REDSHIFT_ALERT_LIST`:
  * description: alert list for generating notifications
  * default: redshift-publicly-accessible,redshift-encrypted,redshift-no-version-upgrade,redshift-no-require-ssl,redshift-no-user-logging

### `AUDIT_AWS_REDSHIFT_ALERT_RECIPIENT`:
  * description: email recipient for notification

### `AUDIT_AWS_REDSHIFT_ALLOW_EMPTY`:
  * description: receive empty reports?

### `AUDIT_AWS_REDSHIFT_PAYLOAD_TYPE`:
  * description: json or text
  * default: json

### `AUDIT_AWS_REDSHIFT_SEND_ON`:
  * description: always or change
  * default: change

### `AUDIT_AWS_REDSHIFT_REGIONS`:
  * description: list of AWS regions to check. Default is all regions
  * default: us-east-1,us-west-1,us-west-2

## Variables Not Required

**None**

## Tags

1. Audit
1. Best Practices
1. Alert
1. Redshift

## Diagram



## Icon



