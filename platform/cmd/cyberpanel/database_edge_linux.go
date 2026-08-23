//go:build linux

package main

import (
	"context"
	"errors"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/database"
	"github.com/aonsyed/cyberpanel/platform/internal/hosting/site"
)

type databaseEdgeRepository interface {
	ListDatabases(context.Context,site.TenantID,string,uint16)([]database.Database,string,uint64,error)
	DatabasePrincipalCount(context.Context,site.TenantID,database.ResourceID)(uint64,error)
}

type databaseEdge struct{repository databaseEdgeRepository}

func newDatabaseEdge(repository databaseEdgeRepository)(apiserver.DatabaseEdgeService,error){if repository==nil{return nil,errors.New("database edge repository is required")};return &databaseEdge{repository:repository},nil}

func(edge *databaseEdge)ListDatabases(ctx context.Context,call apiserver.EdgeCall,page apiserver.EdgePagePayload)(apiserver.EdgePage[apiserver.DatabaseProjection],error){
	tenant,err:=site.NewTenantID(call.TenantID);if err!=nil{return apiserver.EdgePage[apiserver.DatabaseProjection]{},database.ErrInvalidResource};values,next,total,err:=edge.repository.ListDatabases(ctx,tenant,page.Cursor,page.Limit);if err!=nil{return apiserver.EdgePage[apiserver.DatabaseProjection]{},err};items:=make([]apiserver.DatabaseProjection,0,len(values));for _,value:=range values{principals,countErr:=edge.repository.DatabasePrincipalCount(ctx,tenant,value.ID);if countErr!=nil{return apiserver.EdgePage[apiserver.DatabaseProjection]{},countErr};items=append(items,apiserver.DatabaseProjection{ID:value.ID.String(),SiteID:value.SiteID.String(),Name:value.Name.String(),Instance:value.InstanceID.String(),Principals:principals,Status:string(value.Status.Lifecycle),Generation:value.Generation})};return apiserver.EdgePage[apiserver.DatabaseProjection]{Items:items,NextCursor:next,Total:total},nil
}

var _ apiserver.DatabaseEdgeService=(*databaseEdge)(nil)
