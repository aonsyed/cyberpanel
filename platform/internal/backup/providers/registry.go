package providers

import "github.com/aonsyed/cyberpanel/platform/internal/backup"

type ProviderSet struct{Local backup.RepositoryProvider;SFTP backup.RepositoryProvider;S3 backup.RepositoryProvider;GoogleDrive backup.RepositoryProvider}
func (set ProviderSet)Registry()map[backup.ProviderKind]backup.RepositoryProvider{providers:=map[backup.ProviderKind]backup.RepositoryProvider{};if set.Local!=nil{providers[backup.Local]=set.Local};if set.SFTP!=nil{providers[backup.SFTP]=set.SFTP};if set.S3!=nil{for _,kind:=range []backup.ProviderKind{backup.S3,backup.AWS,backup.Wasabi,backup.Backblaze,backup.DigitalOceanSpaces,backup.MinIO}{providers[kind]=set.S3}};if set.GoogleDrive!=nil{providers[backup.GoogleDrive]=set.GoogleDrive};return providers}
func (set ProviderSet)RestoreRegistry()map[backup.ProviderKind]backup.RepositoryRestoreReader{readers:=map[backup.ProviderKind]backup.RepositoryRestoreReader{};register:=func(kind backup.ProviderKind,provider backup.RepositoryProvider){if reader,ok:=provider.(backup.RepositoryRestoreReader);ok{readers[kind]=reader}};register(backup.Local,set.Local);register(backup.SFTP,set.SFTP);for _,kind:=range []backup.ProviderKind{backup.S3,backup.AWS,backup.Wasabi,backup.Backblaze,backup.DigitalOceanSpaces,backup.MinIO}{register(kind,set.S3)};register(backup.GoogleDrive,set.GoogleDrive);return readers}
