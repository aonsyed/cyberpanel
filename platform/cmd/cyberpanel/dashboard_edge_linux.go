//go:build linux

package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
)

type dashboardEdge struct { db *sql.DB; now func() time.Time }

func newDashboardEdge(db *sql.DB, now func() time.Time) (*dashboardEdge,error) {
	if db==nil||now==nil{return nil,errors.New("dashboard authority is required")}
	return &dashboardEdge{db:db,now:now},nil
}

func(edge *dashboardEdge)Summary(ctx context.Context,call apiserver.EdgeCall)(apiserver.DashboardSummary,error){
	if edge==nil||edge.db==nil||ctx==nil{return apiserver.DashboardSummary{},errors.New("dashboard authority is required")}
	hostname,err:=os.Hostname();if err!=nil{return apiserver.DashboardSummary{},err};hostname=strings.TrimSpace(hostname);if hostname==""{hostname="localhost"}
	counts:=apiserver.DashboardCountProjection{}
	tenant:=strings.TrimSpace(call.TenantID)
	queries:=[]struct{target *uint64;tenantSQL,nodeSQL string}{
		{&counts.Sites,`SELECT COUNT(*) FROM hosting_sites WHERE tenant_id=?`,`SELECT COUNT(*) FROM hosting_sites`},
		{&counts.Databases,`SELECT COUNT(*) FROM panel_database_resources WHERE kind='database' AND tenant_id=?`,`SELECT COUNT(*) FROM panel_database_resources WHERE kind='database'`},
		{&counts.Mailboxes,`SELECT COUNT(*) FROM mail_resources_v2 WHERE kind='mailbox' AND tenant_id=?`,`SELECT COUNT(*) FROM mail_resources_v2 WHERE kind='mailbox'`},
		{&counts.Containers,`SELECT COUNT(*) FROM container_workloads WHERE state<>'deleted' AND tenant_id=?`,`SELECT COUNT(*) FROM container_workloads WHERE state<>'deleted'`},
		{&counts.Findings,`SELECT COUNT(*) FROM app_findings f JOIN app_installations i ON i.id=f.installation_id WHERE f.state<>'resolved' AND i.tenant_id=?`,`SELECT COUNT(*) FROM app_findings WHERE state<>'resolved'`},
		{&counts.Operations,`SELECT COUNT(*) FROM panel_operation_receipts WHERE tenant_id=?`,`SELECT COUNT(*) FROM panel_operation_receipts`},
	}
	for _,query:=range queries{var row *sql.Row;if tenant!=""{row=edge.db.QueryRowContext(ctx,query.tenantSQL,tenant)}else{row=edge.db.QueryRowContext(ctx,query.nodeSQL)};if err=row.Scan(query.target);err!=nil{return apiserver.DashboardSummary{},err}}
	now:=edge.now().UTC()
	return apiserver.DashboardSummary{Node:apiserver.DashboardNodeProjection{ID:"local",Hostname:hostname,Health:"healthy",Version:"greenfield",Architecture:runtime.GOARCH,OperatingSystem:readOSReleaseName(),UpdatedAt:now},Counts:counts,Warnings:[]string{},GeneratedAt:now},nil
}

func readOSReleaseName()string{
	raw,err:=os.ReadFile("/etc/os-release");if err!=nil||len(raw)>64<<10{return runtime.GOOS}
	for _,line:=range strings.Split(string(raw),"\n"){if strings.HasPrefix(line,"PRETTY_NAME="){value:=strings.Trim(strings.TrimPrefix(line,"PRETTY_NAME="),"\"");value=strings.TrimSpace(value);if value!=""&&len(value)<=256{return value}}}
	return runtime.GOOS
}
