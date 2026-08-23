package providers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/aonsyed/cyberpanel/platform/internal/backup"
)

type RepositoryHealth string
const(RepositoryHealthy RepositoryHealth="healthy";RepositoryDegraded RepositoryHealth="degraded";RepositoryUnavailable RepositoryHealth="unavailable")
type RepositoryProbe struct{RepositoryID backup.RepositoryID `json:"repository_id"`;Kind backup.ProviderKind `json:"kind"`;Health RepositoryHealth `json:"health"`;Capabilities []string `json:"capabilities"`;Latency time.Duration `json:"latency"`;DetailDigest string `json:"detail_digest"`;ObservedAt time.Time `json:"observed_at"`}
type RepositoryProber interface{ProbeRepository(context.Context,backup.RepositorySpec,string)(RepositoryProbe,error)}
type RepositoryLifecycle struct{DB *sql.DB;Providers map[backup.ProviderKind]backup.RepositoryProvider;Probers map[backup.ProviderKind]RepositoryProber;Now func()time.Time}
const repositoryLifecycleSchema=`CREATE TABLE IF NOT EXISTS backup_repository_health_v2(repository_id TEXT PRIMARY KEY,kind TEXT NOT NULL,health TEXT NOT NULL,probe_json BLOB NOT NULL,observed_at TIMESTAMP NOT NULL);`
func (lifecycle RepositoryLifecycle)Bootstrap(ctx context.Context)error{if lifecycle.DB==nil{return errors.New("backup repository lifecycle database required")};_,err:=lifecycle.DB.ExecContext(ctx,repositoryLifecycleSchema);return err}
func (lifecycle RepositoryLifecycle)Probe(ctx context.Context,spec backup.RepositorySpec,effect string)(RepositoryProbe,error){prober:=lifecycle.Probers[spec.Repository.Kind];if lifecycle.DB==nil||prober==nil||effect==""{return RepositoryProbe{},ErrInvalid};probe,err:=prober.ProbeRepository(ctx,spec,effect);if probe.RepositoryID!=spec.Repository.ID||probe.Kind!=spec.Repository.Kind||probe.ObservedAt.IsZero(){return RepositoryProbe{},errors.Join(ErrIntegrity,err)};sort.Strings(probe.Capabilities);raw,marshalErr:=json.Marshal(probe);if marshalErr!=nil{return probe,marshalErr};if _,saveErr:=lifecycle.DB.ExecContext(ctx,`INSERT INTO backup_repository_health_v2(repository_id,kind,health,probe_json,observed_at) VALUES(?,?,?,?,?) ON CONFLICT(repository_id) DO UPDATE SET kind=excluded.kind,health=excluded.health,probe_json=excluded.probe_json,observed_at=excluded.observed_at`,probe.RepositoryID,probe.Kind,probe.Health,raw,probe.ObservedAt);saveErr!=nil{return probe,errors.Join(err,saveErr)};return probe,err}
func (lifecycle RepositoryLifecycle)Latest(ctx context.Context,repository backup.RepositoryID)(RepositoryProbe,error){if lifecycle.DB==nil||repository==""{return RepositoryProbe{},ErrInvalid};var raw []byte;if err:=lifecycle.DB.QueryRowContext(ctx,`SELECT probe_json FROM backup_repository_health_v2 WHERE repository_id=?`,repository).Scan(&raw);err!=nil{return RepositoryProbe{},err};var probe RepositoryProbe;if err:=json.Unmarshal(raw,&probe);err!=nil{return RepositoryProbe{},err};return probe,nil}
func (set ProviderSet)ProberRegistry()map[backup.ProviderKind]RepositoryProber{probers:=map[backup.ProviderKind]RepositoryProber{};register:=func(kind backup.ProviderKind,provider backup.RepositoryProvider){if prober,ok:=provider.(RepositoryProber);ok{probers[kind]=prober}};register(backup.Local,set.Local);register(backup.SFTP,set.SFTP);for _,kind:=range []backup.ProviderKind{backup.S3,backup.AWS,backup.Wasabi,backup.Backblaze,backup.DigitalOceanSpaces,backup.MinIO}{register(kind,set.S3)};register(backup.GoogleDrive,set.GoogleDrive);return probers}
