package migration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
)

const (
	MaildirManifestVersion   = 1
	MaildirTransportChunkMax = uint32(1 << 20)
	MaildirManifestMaxBytes  = 24 << 20
	MaildirManifestMaxFiles  = 1_000_000
	MaildirMailboxMaxBytes   = uint64(1 << 50)
	MaildirManifestName      = ".cyberpanel-maildir-manifest-v1.json"
	MaildirV1MediaType       = "application/vnd.cyberpanel.migration.maildir-v1+tar"
)

type MaildirTransportChunk struct {
	Offset uint64 `json:"offset"`
	Size   uint32 `json:"size"`
	Digest string `json:"digest"`
}

type MaildirManifestFile struct {
	Path         string   `json:"path"`
	Size         uint64   `json:"size"`
	Digest       string   `json:"digest"`
	FirstChunk   uint64   `json:"first_chunk"`
	ChunkDigests []string `json:"chunk_digests"`
}

type MaildirManifest struct {
	Version     uint8                 `json:"version"`
	ChunkBytes  uint32                `json:"chunk_bytes"`
	Files       []MaildirManifestFile `json:"files"`
	TotalBytes  uint64                `json:"total_bytes"`
	TotalFiles  uint64                `json:"total_files"`
	TotalChunks uint64                `json:"total_chunks"`
	RootDigest  string                `json:"root_digest"`
}

func SealMaildirManifest(files []MaildirManifestFile) (MaildirManifest, error) {
	canonical := make([]MaildirManifestFile, len(files))
	var totalChunks uint64
	for index, file := range files {
		file.ChunkDigests = append(make([]string, 0, len(file.ChunkDigests)), file.ChunkDigests...)
		file.FirstChunk = totalChunks
		totalChunks += uint64(len(file.ChunkDigests))
		canonical[index] = file
	}
	manifest := MaildirManifest{Version: MaildirManifestVersion, ChunkBytes: MaildirTransportChunkMax, Files: canonical, TotalFiles: uint64(len(canonical)), TotalChunks: totalChunks}
	for _, file := range manifest.Files {
		if file.Size > MaildirMailboxMaxBytes || manifest.TotalBytes > MaildirMailboxMaxBytes-file.Size {
			return MaildirManifest{}, ErrCapacity
		}
		manifest.TotalBytes += file.Size
	}
	root, err := maildirManifestRoot(manifest)
	if err != nil {
		return MaildirManifest{}, err
	}
	manifest.RootDigest = root
	if err = manifest.Validate(); err != nil {
		return MaildirManifest{}, err
	}
	return manifest, nil
}

func (manifest MaildirManifest) Validate() error {
	if manifest.Version != MaildirManifestVersion || manifest.ChunkBytes != MaildirTransportChunkMax || manifest.Files == nil || len(manifest.Files) > MaildirManifestMaxFiles || manifest.TotalFiles != uint64(len(manifest.Files)) || manifest.TotalBytes > MaildirMailboxMaxBytes || !maildirDigest(manifest.RootDigest) {
		return ErrInvalid
	}
	var total uint64
	var chunks uint64
	previous := ""
	for _, file := range manifest.Files {
		if !ValidMaildirPath(file.Path) || file.Path <= previous || !maildirDigest(file.Digest) || file.ChunkDigests == nil || file.FirstChunk != chunks || file.Size > MaildirMailboxMaxBytes-total {
			return ErrInvalid
		}
		previous = file.Path
		total += file.Size
		expectedChunks := file.Size / uint64(MaildirTransportChunkMax)
		if file.Size%uint64(MaildirTransportChunkMax) != 0 {
			expectedChunks++
		}
		if uint64(len(file.ChunkDigests)) != expectedChunks {
			return ErrInvalid
		}
		for _, digest := range file.ChunkDigests {
			if !maildirDigest(digest) {
				return ErrInvalid
			}
		}
		chunks += uint64(len(file.ChunkDigests))
	}
	if total != manifest.TotalBytes || chunks != manifest.TotalChunks {
		return ErrInvalid
	}
	root, err := maildirManifestRoot(manifest)
	if err != nil || root != manifest.RootDigest {
		return ErrInvalid
	}
	raw, err := json.Marshal(manifest)
	if err != nil || len(raw) > MaildirManifestMaxBytes {
		return ErrCapacity
	}
	return nil
}

func (manifest MaildirManifest) ChunkCount() uint64 {
	return manifest.TotalChunks
}

func (manifest MaildirManifest) Chunk(sequence uint64) (MaildirManifestFile, MaildirTransportChunk, bool) {
	index := sort.Search(len(manifest.Files), func(index int) bool {
		file := manifest.Files[index]
		return file.FirstChunk+uint64(len(file.ChunkDigests)) > sequence
	})
	if index < len(manifest.Files) {
		file := manifest.Files[index]
		local := sequence - file.FirstChunk
		offset := local * uint64(MaildirTransportChunkMax)
		size := file.Size - offset
		if size > uint64(MaildirTransportChunkMax) {
			size = uint64(MaildirTransportChunkMax)
		}
		return file, MaildirTransportChunk{Offset: offset, Size: uint32(size), Digest: file.ChunkDigests[local]}, true
	}
	return MaildirManifestFile{}, MaildirTransportChunk{}, false
}

func ValidMaildirPath(value string) bool {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] != "cur" && parts[0] != "new" || len(parts[1]) == 0 || len(parts[1]) > 240 || parts[1] == "." || parts[1] == ".." {
		return false
	}
	for _, character := range parts[1] {
		if character < 33 || character > 126 || character == '/' || character == '\\' {
			return false
		}
	}
	return true
}

func maildirManifestRoot(manifest MaildirManifest) (string, error) {
	binding := struct {
		Version     uint8                 `json:"version"`
		ChunkBytes  uint32                `json:"chunk_bytes"`
		Files       []MaildirManifestFile `json:"files"`
		TotalBytes  uint64                `json:"total_bytes"`
		TotalFiles  uint64                `json:"total_files"`
		TotalChunks uint64                `json:"total_chunks"`
	}{Version: manifest.Version, ChunkBytes: manifest.ChunkBytes, Files: manifest.Files, TotalBytes: manifest.TotalBytes, TotalFiles: manifest.TotalFiles, TotalChunks: manifest.TotalChunks}
	raw, err := json.Marshal(binding)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func maildirDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
