package rebootcontrol

import "strings"

// This is a closed inventory of existing durable repositories, not a caller-
// supplied SQL registry. Unknown states remain blockers; no row is resumed or
// deleted by reboot control. JSON arrays preserve composite identities exactly.
type admissionSource struct {
	table string
	ids []string
	state string
	terminal string
	observe string
}

var admissionSources=[]admissionSource{
	{"reboot_api_invocations",[]string{"id"},"status","'completed'",""},
	{"panel_database_operations",[]string{"scope_tenant_id","scope_kind","scope_id","command_id","json_extract(@receipt_json,'$.request.effect_id')"},"status","'applied','rejected','compensated'",""},
	{"database_transfer_state_v1",[]string{"job_id"},"status","'succeeded','completed','failed','canceled','cancelled'",""},
	{"hosting_commands",[]string{"command_id","effect_id"},"status","'applied'",""},
	{"mail_operations_v2",[]string{"command_id"},"status","'applied','rejected','compensated'",""},
	{"mail_queue_admin_operations_v1",[]string{"partition_id","operation_id"},"status","'completed'",""},
	{"dns_changes",[]string{"id"},"CASE WHEN @applied_at IS NULL THEN 'pending' ELSE 'applied' END","'applied'",""},
	{"certificate_orders",[]string{"id"},"json_extract(@order_json,'$.state')","'issued','valid','active','revoked','failed','invalid','canceled','cancelled'",""},
	{"certificate_issuances_v2",[]string{"id"},"phase","'issued','active','revoked','failed'",""},
	{"certificate_renewals_v2",[]string{"id"},"state","'complete','stale'",""},
	{"backup_recovery_points",[]string{"id"},"CASE WHEN EXISTS(SELECT 1 FROM backup_manifests AS m WHERE m.recovery_point_id=@id AND m.committed_at IS NOT NULL) THEN 'committed' ELSE json_extract(@point_json,'$.state') END","'committed'",""},
	{"backup_restores",[]string{"id"},"json_extract(@restore_json,'$.stage')","'promoted'",""},
	{"backup_transfers",[]string{"id"},"json_extract(@transfer_json,'$.state')","'complete'",""},
	{"backup_jobs",[]string{"id"},"json_extract(@job_json,'$.state')","'scheduled','completed','succeeded','failed','canceled','cancelled'",""},
	{"restore_receipts_v2",[]string{"plan_id"},"phase","'active','failed','rolled_back'",""},
	{"backup_retention_executions_v2",[]string{"plan_id"},"state","'complete'",""},
	{"container_operations",[]string{"effect_id"},"status","'applied','rejected'",""},
	{"app_operations",[]string{"command_id"},"state","'committed','failed','compensated'",""},
	{"package_maintenance_operations",[]string{"id"},"state","'succeeded','failed','recovered'",""},
	{"product_update_states",[]string{"manifest_id","node_id"},"phase","'committed','rolled_back','failed'",""},
	{"panel_migrations",[]string{"id","attempt_id"},"phase","'committed','failed_terminal','rolled_back','canceled'",""},
	{"panel_operation_receipts",[]string{"node_id","tenant_id","scope_kind","scope_id","command_id","json_extract(@receipt_json,'$.request.effect_id')"},"status","'applied','rejected','compensated'","COALESCE(json_extract(@receipt_json,'$.request.kind'),'') IN ('query_metrics','query_logs','query_ssh_logins','query_ssh_sessions','investigate_process','diagnose_service','record_transfer_sample')"},
}

func(source admissionSource)stateSQL(prefix string)string{
	if strings.Contains(source.state,"@"){return strings.ReplaceAll(source.state,"@",prefix)}
	return prefix+source.state
}
func(source admissionSource)idSQL(prefix string)string{parts:=make([]string,len(source.ids));for i,id:=range source.ids{if strings.Contains(id,"@"){parts[i]=strings.ReplaceAll(id,"@",prefix)}else{parts[i]=prefix+id}};return "json_array("+strings.Join(parts,",")+")"}
func(source admissionSource)nonterminal(prefix string)string{return "COALESCE("+source.stateSQL(prefix)+",'unknown') NOT IN ("+source.terminal+")"}
func(source admissionSource)mutation(prefix string)string{if source.observe==""{return "1"};return "NOT ("+strings.ReplaceAll(source.observe,"@",prefix)+")"}

const admissionClosedSQL=`(EXISTS(SELECT 1 FROM reboot_admission_gate WHERE singleton=1 AND closed=1) OR EXISTS(SELECT 1 FROM reboot_states WHERE node_id='local' AND phase IN ('draining','checkpointed','armed','reboot_dispatched','reconciling','uncertain')))`

func mutationGateExempt(operation string)bool{
	switch operation{case "reboot_control.execute","reboot_control.cancel","reboot_control.reconcile":return true;default:return false}
}
