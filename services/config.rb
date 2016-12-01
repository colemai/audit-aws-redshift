
coreo_aws_advisor_alert "redshift-publicly-accessible" do
  action :define
  service :redshift
  link "http://kb.cloudcoreo.com/mydoc_redshift-publicly-accessible.html"
  display_name "Redshift cluster is Publicly Accessible"
  description "The affected Redshift cluster is publicly accessible to the world."
  category "Security"
  suggested_action "Consider whether the affected Redshift cluster should be publicly accessible to the world. If not, modify the option which enables your Redshift cluster to become publicly accessible."
  level "Alert"
  objectives ["clusters"]
  audit_objects ["clusters.publicly_accessible"]
  operators ["=="]
  alert_when [true]
end

coreo_aws_advisor_alert "redshift-encrypted" do
  action :define
  service :redshift
  link "http://kb.cloudcoreo.com/mydoc_redshift-encrypted.html"
  display_name "Redshift cluster data is not encrypted"
  description "Redshift cluster data in the affected cluster is not encrypted at rest."
  category "Security"
  suggested_action "To encrypt the data in all your user-created tables, you can enable cluster encryption when you launch the cluster."
  level "Warning"
  objectives ["clusters"]
  audit_objects ["clusters.encrypted"]
  operators ["=="]
  alert_when [false]
end

coreo_aws_advisor_alert "redshift-no-version-upgrade" do
  action :define
  service :redshift
  link "http://kb.cloudcoreo.com/mydoc_redshift-no-version-upgrade.html"
  display_name "Redshift automatic major version upgrades not enabled"
  description "Redshift automatic major version upgrades not enabled."
  category "Reliability"
  suggested_action "Enable major version upgrades by setting Allow Version Upgrade to true. This will allow major version upgrades to be applied automatically to the cluster during the maintenance window."
  level "Warning"
  objectives ["clusters"]
  audit_objects ["clusters.allow_version_upgrade"]
  operators ["=="]
  alert_when [false]
end

coreo_aws_advisor_alert "redshift-no-require-ssl" do
  action :define
  service :redshift
  link "http://kb.cloudcoreo.com/mydoc_redshift-no-require-ssl.html"
  display_name "Connections to Redshift not required to use SSL encryption"
  description "Connections to Redshift aren't set to require the use of SSL encryption."
  category "Security"
  suggested_action "Enable Redshift to require the use of SSL encrypted connections."
  level "Critical"
  objectives     ["cluster_parameter_groups", "cluster_parameters", "cluster_parameters"]
  call_modifiers [{}, {:parameter_group_name => "parameter_groups.parameter_group_name"}, {:parameter_group_name => "parameter_groups.parameter_group_name"}]
  id_map "modifiers.parameter_group_name"
  audit_objects  ["", "parameters.parameter_name", "parameters.parameter_value"]
  operators      ["", "==", "=="]
  alert_when     ["", "require_ssl", false]
end

coreo_aws_advisor_alert "redshift-no-user-logging" do
  action :define
  service :redshift
  link "http://kb.cloudcoreo.com/mydoc_redshift-no-user-logging.html"
  display_name "Redshift user activity logging is disabled"
  description "Redshift user activity logging is disabled."
  category "Audit"
  suggested_action "Enable Redshift user activity logging."
  level "Warning"
  objectives ["cluster_parameter_groups", "cluster_parameters", "cluster_parameters"]
  call_modifiers [{}, {:parameter_group_name => "parameter_groups.parameter_group_name"}, {:parameter_group_name => "parameter_groups.parameter_group_name"}]
  id_map "modifiers.parameter_group_name"
  audit_objects ["", "parameters.parameter_name", "parameters.parameter_value"]
  operators ["", "==", "=="]
  alert_when ["", "enable_user_activity_logging", false]
end

coreo_aws_advisor_alert "redshift-snapshot-retention" do
  action :define
  service :redshift
  #link "http://kb.cloudcoreo.com/"
  display_name "Redshift short snapshot retention period"
  description "The affected Redshift cluster has a short snapshot retention period."
  category "Dataloss"
  suggested_action "Increase the snapshot retention period for the affected Redshift cluster."
  level "Critical"
  objectives ["clusters"]
  id_map "object.clusters.cluster_identifier"
  audit_objects ["object.clusters.automated_snapshot_retention_period"]
  operators ["<="]
  alert_when [10]
end

coreo_aws_advisor_redshift "advise-redshift" do
  alerts ${AUDIT_AWS_REDSHIFT_ALERT_LIST}
  action :advise
  regions ${AUDIT_AWS_REDSHIFT_REGIONS}
end

=begin
  START AWS REDSHIFT METHODS
  JSON SEND METHOD
  HTML SEND METHOD
=end
coreo_uni_util_notify "advise-redshift-json" do
  action :${AUDIT_AWS_REDSHIFT_FULL_JSON_REPORT}
  type 'email'
  allow_empty ${AUDIT_AWS_REDSHIFT_ALLOW_EMPTY}
  send_on ${AUDIT_AWS_REDSHIFT_SEND_ON}
  payload '{"composite name":"PLAN::stack_name",
  "plan name":"PLAN::name",
  "number_of_checks":"COMPOSITE::coreo_aws_advisor_redshift.advise-redshift.number_checks",
  "number_of_violations":"COMPOSITE::coreo_aws_advisor_redshift.advise-redshift.number_violations",
  "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_redshift.advise-redshift.number_ignored_violations",
  "violations": COMPOSITE::coreo_aws_advisor_redshift.advise-redshift.report }'
  payload_type "json"
  endpoint ({
      :to => '${AUDIT_AWS_REDSHIFT_ALERT_RECIPIENT}', :subject => 'CloudCoreo redshift advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-redshift" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.0.9"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "number_of_checks":"COMPOSITE::coreo_aws_advisor_redshift.advise-redshift.number_checks",
                "number_of_violations":"COMPOSITE::coreo_aws_advisor_redshift.advise-redshift.number_violations",
                "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_redshift.advise-redshift.number_ignored_violations",
                "violations": COMPOSITE::coreo_aws_advisor_redshift.advise-redshift.report}'
  function <<-EOH
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditRedshift = new CloudCoreoJSRunner(json_input, false, "${AUDIT_AWS_REDSHIFT_RECIPIENT_2}", "${AUDIT_AWS_REDSHIFT_OWNER_TAG}", 'redshift');
const notifiers = AuditRedshift.getNotifiers();
callback(notifiers);
  EOH
end

coreo_uni_util_jsrunner "tags-rollup-redshift" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-redshift.return'
  function <<-EOH
var rollup_string = "";
for (var entry=0; entry < json_input.length; entry++) {
  console.log(json_input[entry]);
  if (json_input[entry]['endpoint']['to'].length) {
    console.log('got an email to rollup');
    rollup_string = rollup_string + "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "nViolations: " + json_input[entry]['num_violations'] + "\\n";
  }
}
callback(rollup_string);
  EOH
end

coreo_uni_util_notify "advise-redshift-to-tag-values" do
  action :${AUDIT_AWS_REDSHIFT_OWNERS_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-redshift.return'
end

coreo_uni_util_notify "advise-redshift-rollup" do
  action :${AUDIT_AWS_REDSHIFT_ROLLUP_REPORT}
  type 'email'
  allow_empty true
  send_on 'always'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
number_of_checks: COMPOSITE::coreo_aws_advisor_redshift.advise-redshift.number_checks
number_of_violations: COMPOSITE::coreo_aws_advisor_redshift.advise-redshift.number_violations
number_violations_ignored: COMPOSITE::coreo_aws_advisor_redshift.advise-redshift.number_ignored_violations

rollup report:
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup-redshift.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_REDSHIFT_RECIPIENT_2}', :subject => 'CloudCoreo redshift advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end
=begin
  AWS REDSHIFT END
=end

