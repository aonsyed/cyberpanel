package webmail

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type DovecotBackend struct {
	endpoint Endpoint
}

func NewDovecotBackend(endpoint Endpoint) (*DovecotBackend, error) {
	if !endpoint.valid() {
		return nil, ErrInvalid
	}
	return &DovecotBackend{endpoint: endpoint}, nil
}

func (backend *DovecotBackend) connect(ctx context.Context, bearer string) (*imapClient, error) {
	if backend == nil || !backend.endpoint.valid() {
		return nil, ErrInvalid
	}
	return dialIMAP(ctx, backend.endpoint, bearer)
}

func (backend *DovecotBackend) ListFolders(ctx context.Context, bearer string, request FolderPageRequest) (FolderPage, error) {
	if ctx == nil || request.Limit == 0 || request.Limit > MaximumPageSize || request.Cursor != "" {
		return FolderPage{}, ErrInvalid
	}
	client, err := backend.connect(ctx, bearer)
	if err != nil {
		return FolderPage{}, err
	}
	defer client.close()
	lines, err := client.command(`LIST "" "*" RETURN (SUBSCRIBED CHILDREN SPECIAL-USE STATUS (MESSAGES UNSEEN UIDNEXT UIDVALIDITY HIGHESTMODSEQ))`)
	if err != nil {
		return FolderPage{}, err
	}
	quota, err := readQuota(client)
	if err != nil {
		return FolderPage{}, err
	}
	folders, err := parseFolders(lines, quota)
	if err != nil {
		return FolderPage{}, err
	}
	sort.Slice(folders, func(left, right int) bool { return folders[left].Name < folders[right].Name })
	start := sort.Search(len(folders), func(index int) bool { return folders[index].Name > request.afterName })
	end := start + int(request.Limit)
	more := false
	if end < len(folders) {
		more = true
	} else {
		end = len(folders)
	}
	page := FolderPage{Folders: append([]Folder(nil), folders[start:end]...), more: more}
	return page, nil
}

func readQuota(client *imapClient) (Quota, error) {
	lines, err := client.command(`GETQUOTAROOT "INBOX"`)
	if err != nil {
		return Quota{}, err
	}
	var quota Quota
	found := false
	for _, line := range lines {
		values, parseErr := parseIMAPValues(line)
		if parseErr != nil || len(values) < 4 || values[0].atom != "*" || !strings.EqualFold(values[1].atom, "QUOTA") || values[3].list == nil {
			continue
		}
		items := values[3].list
		for index := 0; index+2 < len(items); index += 3 {
			if !strings.EqualFold(items[index].atom, "STORAGE") {
				continue
			}
			used, usedErr := strconv.ParseUint(items[index+1].atom, 10, 64)
			limit, limitErr := strconv.ParseUint(items[index+2].atom, 10, 64)
			if usedErr != nil || limitErr != nil || used > ^uint64(0)/1024 || limit > ^uint64(0)/1024 || found {
				return Quota{}, ErrAmbiguous
			}
			quota = Quota{UsedBytes: used * 1024, LimitBytes: limit * 1024}
			found = true
		}
	}
	if !found {
		return Quota{}, ErrProtocol
	}
	return quota, nil
}

func parseFolders(lines []string, quota Quota) ([]Folder, error) {
	folders := make(map[string]Folder)
	statuses := make(map[string]map[string]uint64)
	for _, line := range lines {
		values, err := parseIMAPValues(line)
		if err != nil || len(values) < 2 || values[0].atom != "*" {
			return nil, ErrProtocol
		}
		switch strings.ToUpper(values[1].atom) {
		case "LIST":
			if len(values) != 5 && len(values) != 7 || values[2].list == nil {
				return nil, ErrProtocol
			}
			name, decodeErr := decodeMailbox(values[4].atom)
			if decodeErr != nil {
				return nil, decodeErr
			}
			if _, exists := folders[name]; exists {
				return nil, ErrAmbiguous
			}
			delimiterRunes := []rune(values[3].atom)
			if len(delimiterRunes) != 1 {
				return nil, ErrProtocol
			}
			folder := Folder{Name: name, Delimiter: delimiterRunes[0], Quota: quota}
			for _, flag := range values[2].list {
				switch strings.ToLower(flag.atom) {
				case `\subscribed`:
					folder.Subscribed = true
				case `\haschildren`:
					folder.HasChildren = true
				case `\inbox`:
					folder.SpecialUse = SpecialInbox
				case `\archive`:
					folder.SpecialUse = SpecialArchive
				case `\drafts`:
					folder.SpecialUse = SpecialDrafts
				case `\junk`:
					folder.SpecialUse = SpecialJunk
				case `\sent`:
					folder.SpecialUse = SpecialSent
				case `\trash`:
					folder.SpecialUse = SpecialTrash
				case `\flagged`:
					folder.SpecialUse = SpecialFlagged
				case `\all`:
					folder.SpecialUse = SpecialAll
				}
			}
			if strings.EqualFold(name, "INBOX") {
				folder.SpecialUse = SpecialInbox
			}
			if position := strings.LastIndex(name, string(folder.Delimiter)); position >= 0 {
				folder.Parent = name[:position]
			}
			folders[name] = folder
			if len(values) == 7 {
				if !strings.EqualFold(values[5].atom, "STATUS") || values[6].list == nil || len(values[6].list)%2 != 0 {
					return nil, ErrProtocol
				}
				status := make(map[string]uint64)
				for index := 0; index < len(values[6].list); index += 2 {
					value, valueErr := strconv.ParseUint(values[6].list[index+1].atom, 10, 64)
					if valueErr != nil {
						return nil, ErrProtocol
					}
					status[strings.ToUpper(values[6].list[index].atom)] = value
				}
				statuses[name] = status
			}
		case "STATUS":
			if len(values) != 4 || values[3].list == nil {
				return nil, ErrProtocol
			}
			name, decodeErr := decodeMailbox(values[2].atom)
			if decodeErr != nil || len(values[3].list)%2 != 0 {
				return nil, ErrProtocol
			}
			if _, exists := statuses[name]; exists {
				return nil, ErrAmbiguous
			}
			status := make(map[string]uint64)
			for index := 0; index < len(values[3].list); index += 2 {
				value, valueErr := strconv.ParseUint(values[3].list[index+1].atom, 10, 64)
				if valueErr != nil {
					return nil, ErrProtocol
				}
				status[strings.ToUpper(values[3].list[index].atom)] = value
			}
			statuses[name] = status
		default:
			return nil, ErrProtocol
		}
	}
	result := make([]Folder, 0, len(folders))
	for name, folder := range folders {
		status, ok := statuses[name]
		_, hasMessages := status["MESSAGES"]
		_, hasUnseen := status["UNSEEN"]
		_, hasUIDNext := status["UIDNEXT"]
		_, hasUIDValidity := status["UIDVALIDITY"]
		_, hasModSeq := status["HIGHESTMODSEQ"]
		if !ok || !hasMessages || !hasUnseen || !hasUIDNext || !hasUIDValidity || !hasModSeq ||
			status["UIDVALIDITY"] == 0 || status["UIDNEXT"] == 0 || status["HIGHESTMODSEQ"] == 0 ||
			status["UIDVALIDITY"] > uint64(^uint32(0)) || status["UIDNEXT"] > uint64(^uint32(0)) ||
			status["MESSAGES"] > uint64(^uint32(0)) || status["UNSEEN"] > uint64(^uint32(0)) {
			return nil, ErrProtocol
		}
		folder.Messages = uint32(status["MESSAGES"])
		folder.Unseen = uint32(status["UNSEEN"])
		folder.UIDNext = uint32(status["UIDNEXT"])
		folder.UIDValidity = uint32(status["UIDVALIDITY"])
		folder.HighestModSeq = status["HIGHESTMODSEQ"]
		result = append(result, folder)
	}
	return result, nil
}

func (backend *DovecotBackend) MutateFolder(ctx context.Context, bearer string, request FolderMutationRequest) error {
	if ctx == nil || !request.valid() {
		return ErrInvalid
	}
	client, err := backend.connect(ctx, bearer)
	if err != nil {
		return err
	}
	defer client.close()
	encoded, err := encodeMailbox(request.Name)
	if err != nil {
		return err
	}
	quoted, err := imapQuote(encoded)
	if err != nil {
		return err
	}
	if request.Operation != FolderCreate {
		eligible, eligibilityErr := folderEligible(client, encoded)
		if eligibilityErr != nil {
			return eligibilityErr
		}
		if !eligible {
			return ErrIneligibleFolder
		}
	}
	switch request.Operation {
	case FolderCreate:
		if strings.EqualFold(request.Name, "INBOX") {
			return ErrIneligibleFolder
		}
		_, err = client.command("CREATE " + quoted)
	case FolderRename:
		newEncoded, encodeErr := encodeMailbox(request.NewName)
		if encodeErr != nil {
			return encodeErr
		}
		newQuoted, quoteErr := imapQuote(newEncoded)
		if quoteErr != nil {
			return quoteErr
		}
		if strings.EqualFold(request.NewName, "INBOX") {
			return ErrIneligibleFolder
		}
		_, err = client.command("RENAME " + quoted + " " + newQuoted)
	case FolderSubscribe:
		_, err = client.command("SUBSCRIBE " + quoted)
	case FolderUnsubscribe:
		_, err = client.command("UNSUBSCRIBE " + quoted)
	case FolderEmpty:
		if _, err = client.command("SELECT " + quoted); err == nil {
			if _, err = client.command(`UID STORE 1:* +FLAGS.SILENT (\Deleted)`); err == nil {
				_, err = client.command("EXPUNGE")
			}
		}
	case FolderDelete:
		_, err = client.command("DELETE " + quoted)
	default:
		return ErrInvalid
	}
	return err
}

func folderEligible(client *imapClient, encoded string) (bool, error) {
	quoted, err := imapQuote(encoded)
	if err != nil {
		return false, err
	}
	lines, err := client.command(`LIST "" ` + quoted + ` RETURN (SPECIAL-USE)`)
	if err != nil {
		return false, err
	}
	found := false
	for _, line := range lines {
		values, parseErr := parseIMAPValues(line)
		if parseErr != nil || len(values) != 5 || values[0].atom != "*" || !strings.EqualFold(values[1].atom, "LIST") || values[2].list == nil {
			return false, ErrProtocol
		}
		name, decodeErr := decodeMailbox(values[4].atom)
		if decodeErr != nil || found {
			return false, ErrAmbiguous
		}
		found = true
		if strings.EqualFold(name, "INBOX") {
			return false, nil
		}
		for _, flag := range values[2].list {
			switch strings.ToLower(flag.atom) {
			case `\archive`, `\drafts`, `\junk`, `\sent`, `\trash`, `\flagged`, `\all`, `\noselect`:
				return false, nil
			}
		}
	}
	if !found {
		return false, ErrNotFound
	}
	return true, nil
}

type selectedMailbox struct {
	UIDValidity   uint32
	HighestModSeq uint64
}

func selectMailbox(client *imapClient, folder string) (selectedMailbox, error) {
	return openMailbox(client, folder, true)
}

func openMailbox(client *imapClient, folder string, readOnly bool) (selectedMailbox, error) {
	encoded, err := encodeMailbox(folder)
	if err != nil {
		return selectedMailbox{}, err
	}
	quoted, err := imapQuote(encoded)
	if err != nil {
		return selectedMailbox{}, err
	}
	verb := "SELECT"
	if readOnly {
		verb = "EXAMINE"
	}
	lines, err := client.command(verb + " " + quoted + " (CONDSTORE)")
	if err != nil {
		return selectedMailbox{}, err
	}
	var selected selectedMailbox
	for _, line := range lines {
		upper := strings.ToUpper(line)
		if value, ok := responseCodeNumber(upper, "UIDVALIDITY"); ok {
			if selected.UIDValidity != 0 || value == 0 || value > uint64(^uint32(0)) {
				return selectedMailbox{}, ErrAmbiguous
			}
			selected.UIDValidity = uint32(value)
		}
		if value, ok := responseCodeNumber(upper, "HIGHESTMODSEQ"); ok {
			if selected.HighestModSeq != 0 {
				return selectedMailbox{}, ErrAmbiguous
			}
			selected.HighestModSeq = value
		}
	}
	if selected.UIDValidity == 0 || selected.HighestModSeq == 0 {
		return selectedMailbox{}, ErrProtocol
	}
	return selected, nil
}

func (backend *DovecotBackend) OpenMessage(ctx context.Context, bearer string, identity MessageIdentity, maximum uint64) (io.ReadCloser, error) {
	if ctx == nil || !identity.valid() || maximum == 0 || maximum > MaximumRawMessageBytes {
		return nil, ErrInvalid
	}
	client, err := backend.connect(ctx, bearer)
	if err != nil {
		return nil, err
	}
	selected, err := selectMailbox(client, identity.Folder)
	if err != nil {
		client.close()
		return nil, err
	}
	if selected.UIDValidity != identity.UIDValidity {
		client.close()
		return nil, ErrStaleUIDValidity
	}
	reader, _, err := client.literalCommand("UID FETCH "+strconv.FormatUint(uint64(identity.UID), 10)+" (UID BODY.PEEK[])", identity.UID, maximum)
	if err != nil {
		client.close()
		return nil, err
	}
	return reader, nil
}

func (backend *DovecotBackend) OpenPart(ctx context.Context, bearer string, identity MessageIdentity, partID string, maximum uint64) (io.ReadCloser, uint64, error) {
	if ctx == nil || !identity.valid() || len(partID) > 128 || !partIDPattern.MatchString(partID) || maximum == 0 || maximum > MaximumAttachmentBytes {
		return nil, 0, ErrInvalid
	}
	client, err := backend.connect(ctx, bearer)
	if err != nil {
		return nil, 0, err
	}
	selected, err := selectMailbox(client, identity.Folder)
	if err != nil {
		client.close()
		return nil, 0, err
	}
	if selected.UIDValidity != identity.UIDValidity {
		client.close()
		return nil, 0, ErrStaleUIDValidity
	}
	command := "UID FETCH " + strconv.FormatUint(uint64(identity.UID), 10) + " (UID BINARY.PEEK[" + partID + "])"
	reader, size, err := client.literalCommand(command, identity.UID, maximum)
	if err != nil {
		client.close()
		return nil, 0, err
	}
	return reader, size, nil
}

func (backend *DovecotBackend) ApplyMessages(ctx context.Context, bearer string, request MessageActionRequest) (MessageActionResult, error) {
	if ctx == nil || !request.valid() {
		return MessageActionResult{}, ErrInvalid
	}
	client, err := backend.connect(ctx, bearer)
	if err != nil {
		return MessageActionResult{}, err
	}
	defer client.close()
	selected, err := openMailbox(client, request.Messages[0].Folder, false)
	if err != nil {
		return MessageActionResult{}, err
	}
	if selected.UIDValidity != request.Messages[0].UIDValidity {
		return MessageActionResult{}, ErrStaleUIDValidity
	}
	uids := make([]uint32, len(request.Messages))
	for index, identity := range request.Messages {
		uids[index] = identity.UID
	}
	sort.Slice(uids, func(left, right int) bool { return uids[left] < uids[right] })
	uidParts := make([]string, len(uids))
	for index, uid := range uids {
		uidParts[index] = strconv.FormatUint(uint64(uid), 10)
	}
	uidSet := strings.Join(uidParts, ",")
	searchLines, err := client.command("UID SEARCH RETURN (PARTIAL 1:" + strconv.Itoa(len(uids)+1) + ") UID " + uidSet)
	if err != nil {
		return MessageActionResult{}, err
	}
	foundUIDs, err := parseESearch(searchLines, len(uids)+1)
	if err != nil || len(foundUIDs) != len(uids) {
		return MessageActionResult{}, errors.Join(ErrConflict, err)
	}
	found := make(map[uint32]bool, len(foundUIDs))
	for _, uid := range foundUIDs {
		found[uid] = true
	}
	for _, uid := range uids {
		if !found[uid] {
			return MessageActionResult{}, ErrConflict
		}
	}
	command := ""
	switch request.Action {
	case ActionMove, ActionArchive, ActionSpam, ActionNotSpam:
		target, encodeErr := encodeMailbox(request.TargetFolder)
		if encodeErr != nil {
			return MessageActionResult{}, encodeErr
		}
		quoted, quoteErr := imapQuote(target)
		if quoteErr != nil {
			return MessageActionResult{}, quoteErr
		}
		command = "UID MOVE " + uidSet + " " + quoted
	case ActionCopy:
		target, encodeErr := encodeMailbox(request.TargetFolder)
		if encodeErr != nil {
			return MessageActionResult{}, encodeErr
		}
		quoted, quoteErr := imapQuote(target)
		if quoteErr != nil {
			return MessageActionResult{}, quoteErr
		}
		command = "UID COPY " + uidSet + " " + quoted
	case ActionDelete:
		command = `UID STORE ` + uidSet + ` +FLAGS.SILENT (\Deleted)`
	case ActionUndelete:
		command = `UID STORE ` + uidSet + ` -FLAGS.SILENT (\Deleted)`
	case ActionRead:
		command = `UID STORE ` + uidSet + ` +FLAGS.SILENT (\Seen)`
	case ActionUnread:
		command = `UID STORE ` + uidSet + ` -FLAGS.SILENT (\Seen)`
	case ActionFlag:
		command = `UID STORE ` + uidSet + ` +FLAGS.SILENT (\Flagged)`
	case ActionUnflag:
		command = `UID STORE ` + uidSet + ` -FLAGS.SILENT (\Flagged)`
	default:
		return MessageActionResult{}, ErrInvalid
	}
	if _, err = client.command(command); err != nil {
		return MessageActionResult{}, err
	}
	status, err := mailboxStatus(client, request.Messages[0].Folder)
	if err != nil || status.UIDValidity != selected.UIDValidity {
		return MessageActionResult{}, errors.Join(ErrPartial, err)
	}
	return MessageActionResult{Action: request.Action, Affected: uint16(len(request.Messages)),
		UIDValidity: status.UIDValidity, HighestModSeq: status.HighestModSeq}, nil
}

func mailboxStatus(client *imapClient, folder string) (selectedMailbox, error) {
	encoded, err := encodeMailbox(folder)
	if err != nil {
		return selectedMailbox{}, err
	}
	quoted, err := imapQuote(encoded)
	if err != nil {
		return selectedMailbox{}, err
	}
	lines, err := client.command("STATUS " + quoted + " (UIDVALIDITY HIGHESTMODSEQ)")
	if err != nil {
		return selectedMailbox{}, err
	}
	var status selectedMailbox
	for _, line := range lines {
		values, parseErr := parseIMAPValues(line)
		if parseErr != nil || len(values) != 4 || values[0].atom != "*" || !strings.EqualFold(values[1].atom, "STATUS") || values[3].list == nil || len(values[3].list)%2 != 0 {
			return selectedMailbox{}, ErrProtocol
		}
		for index := 0; index < len(values[3].list); index += 2 {
			value, valueErr := strconv.ParseUint(values[3].list[index+1].atom, 10, 64)
			if valueErr != nil {
				return selectedMailbox{}, ErrProtocol
			}
			switch strings.ToUpper(values[3].list[index].atom) {
			case "UIDVALIDITY":
				if status.UIDValidity != 0 || value == 0 || value > uint64(^uint32(0)) {
					return selectedMailbox{}, ErrAmbiguous
				}
				status.UIDValidity = uint32(value)
			case "HIGHESTMODSEQ":
				if status.HighestModSeq != 0 || value == 0 {
					return selectedMailbox{}, ErrAmbiguous
				}
				status.HighestModSeq = value
			default:
				return selectedMailbox{}, ErrProtocol
			}
		}
	}
	if status.UIDValidity == 0 || status.HighestModSeq == 0 {
		return selectedMailbox{}, ErrProtocol
	}
	return status, nil
}

func responseCodeNumber(line, code string) (uint64, bool) {
	marker := "[" + code + " "
	start := strings.Index(line, marker)
	if start < 0 {
		return 0, false
	}
	start += len(marker)
	end := strings.IndexByte(line[start:], ']')
	if end < 0 {
		return 0, false
	}
	value, err := strconv.ParseUint(line[start:start+end], 10, 64)
	return value, err == nil
}

func (backend *DovecotBackend) ListMessages(ctx context.Context, bearer string, request MessagePageRequest) (MessagePage, error) {
	if ctx == nil || !validMailboxName(request.Folder) || request.Limit == 0 || request.Limit > MaximumPageSize || !request.Sort.valid() || request.Cursor != "" {
		return MessagePage{}, ErrInvalid
	}
	client, err := backend.connect(ctx, bearer)
	if err != nil {
		return MessagePage{}, err
	}
	defer client.close()
	selected, err := selectMailbox(client, request.Folder)
	if err != nil {
		return MessagePage{}, err
	}
	if request.expectedUIDValidity != 0 && request.expectedUIDValidity != selected.UIDValidity {
		return MessagePage{}, ErrStaleUIDValidity
	}
	uids, more, err := boundedUIDSearch(client, request.Sort, request.afterUID, int(request.Limit)+1, "ALL")
	if err != nil {
		return MessagePage{}, err
	}
	if len(uids) > int(request.Limit) {
		uids = uids[:request.Limit]
		more = true
	}
	page := MessagePage{Folder: request.Folder, UIDValidity: selected.UIDValidity, HighestModSeq: selected.HighestModSeq, more: more}
	if len(uids) == 0 {
		return page, nil
	}
	summaries, err := fetchSummaries(client, request.Folder, selected.UIDValidity, uids, request.Threaded)
	if err != nil {
		return MessagePage{}, err
	}
	page.Messages = summaries
	page.lastUID = uids[len(uids)-1]
	return page, nil
}

func boundedUIDSearch(client *imapClient, order MessageSort, afterUID uint32, limit int, criteria string) ([]uint32, bool, error) {
	if limit < 1 || limit > MaximumPageSize+1 || !order.valid() || strings.ContainsAny(criteria, "\x00\r\n") {
		return nil, false, ErrInvalid
	}
	rangeCriterion := "UID 1:*"
	partial := "1:" + strconv.Itoa(limit)
	if order == SortNewest {
		partial = "-" + strconv.Itoa(limit) + ":-1"
		if afterUID > 0 {
			if afterUID == 1 {
				return nil, false, nil
			}
			rangeCriterion = "UID 1:" + strconv.FormatUint(uint64(afterUID-1), 10)
		}
	} else if afterUID > 0 {
		if afterUID == ^uint32(0) {
			return nil, false, nil
		}
		rangeCriterion = "UID " + strconv.FormatUint(uint64(afterUID+1), 10) + ":*"
	}
	lines, err := client.command("UID SEARCH RETURN (PARTIAL " + partial + ") CHARSET UTF-8 " + rangeCriterion + " " + criteria)
	if err != nil {
		return nil, false, err
	}
	uids, err := parseESearch(lines, limit)
	if err != nil {
		return nil, false, err
	}
	sort.Slice(uids, func(left, right int) bool {
		if order == SortNewest {
			return uids[left] > uids[right]
		}
		return uids[left] < uids[right]
	})
	return uids, len(uids) == limit, nil
}

func parseESearch(lines []string, maximum int) ([]uint32, error) {
	var result []uint32
	found := false
	for _, line := range lines {
		values, err := parseIMAPValues(line)
		if err != nil || len(values) < 4 || values[0].atom != "*" || !strings.EqualFold(values[1].atom, "ESEARCH") {
			return nil, ErrProtocol
		}
		if found {
			return nil, ErrAmbiguous
		}
		found = true
		for index := 2; index+1 < len(values); index++ {
			if strings.EqualFold(values[index].atom, "PARTIAL") && values[index+1].list != nil && len(values[index+1].list) == 2 {
				result, err = expandUIDSet(values[index+1].list[1].atom, maximum)
				if err != nil {
					return nil, err
				}
				break
			}
		}
	}
	if !found {
		return nil, ErrProtocol
	}
	return result, nil
}

func expandUIDSet(value string, maximum int) ([]uint32, error) {
	if value == "" {
		return nil, nil
	}
	result := make([]uint32, 0, maximum)
	seen := make(map[uint32]bool)
	for _, item := range strings.Split(value, ",") {
		bounds := strings.Split(item, ":")
		if len(bounds) > 2 {
			return nil, ErrProtocol
		}
		first, err := strconv.ParseUint(bounds[0], 10, 32)
		if err != nil || first == 0 {
			return nil, ErrProtocol
		}
		last := first
		if len(bounds) == 2 {
			last, err = strconv.ParseUint(bounds[1], 10, 32)
			if err != nil || last == 0 {
				return nil, ErrProtocol
			}
		}
		step := int64(1)
		if last < first {
			step = -1
		}
		for current := int64(first); ; current += step {
			uid := uint32(current)
			if !seen[uid] {
				if len(result) >= maximum {
					return nil, ErrPartial
				}
				seen[uid] = true
				result = append(result, uid)
			}
			if current == int64(last) {
				break
			}
		}
	}
	return result, nil
}

func fetchSummaries(client *imapClient, folder string, uidValidity uint32, uids []uint32, threaded bool) ([]MessageSummary, error) {
	uidSet := make([]string, len(uids))
	for index, uid := range uids {
		uidSet[index] = strconv.FormatUint(uint64(uid), 10)
	}
	lines, err := client.command("UID FETCH " + strings.Join(uidSet, ",") + " (UID FLAGS INTERNALDATE RFC822.SIZE ENVELOPE BODYSTRUCTURE MODSEQ)")
	if err != nil {
		return nil, err
	}
	byUID := make(map[uint32]MessageSummary, len(uids))
	for _, line := range lines {
		summary, parseErr := parseFetchSummary(line, folder, uidValidity, threaded)
		if parseErr != nil {
			return nil, parseErr
		}
		if _, exists := byUID[summary.Identity.UID]; exists {
			return nil, ErrAmbiguous
		}
		byUID[summary.Identity.UID] = summary
	}
	if len(byUID) != len(uids) {
		return nil, ErrPartial
	}
	result := make([]MessageSummary, 0, len(uids))
	for _, uid := range uids {
		summary, ok := byUID[uid]
		if !ok {
			return nil, ErrPartial
		}
		result = append(result, summary)
	}
	return result, nil
}

func parseFetchSummary(line, folder string, uidValidity uint32, threaded bool) (MessageSummary, error) {
	values, err := parseIMAPValues(line)
	if err != nil || len(values) != 4 || values[0].atom != "*" || !strings.EqualFold(values[2].atom, "FETCH") || values[3].list == nil {
		return MessageSummary{}, ErrProtocol
	}
	items := values[3].list
	if len(items)%2 != 0 {
		return MessageSummary{}, ErrProtocol
	}
	fields := make(map[string]imapValue)
	seenFields := make(map[string]bool)
	for index := 0; index+1 < len(items); index += 2 {
		key := strings.ToUpper(items[index].atom)
		if key == "" || seenFields[key] {
			return MessageSummary{}, ErrAmbiguous
		}
		seenFields[key] = true
		fields[key] = items[index+1]
	}
	uidValue, uidErr := strconv.ParseUint(fields["UID"].atom, 10, 32)
	size, sizeErr := strconv.ParseUint(fields["RFC822.SIZE"].atom, 10, 64)
	internalDate := strings.TrimSpace(fields["INTERNALDATE"].atom)
	if len(internalDate) > 1 && internalDate[1] == '-' {
		internalDate = "0" + internalDate
	}
	date, dateErr := time.Parse("02-Jan-2006 15:04:05 -0700", internalDate)
	modSeq := uint64(0)
	if fields["MODSEQ"].list != nil && len(fields["MODSEQ"].list) == 1 {
		modSeq, err = strconv.ParseUint(fields["MODSEQ"].list[0].atom, 10, 64)
	}
	envelope := fields["ENVELOPE"].list
	if uidErr != nil || uidValue == 0 || sizeErr != nil || dateErr != nil || err != nil || modSeq == 0 || len(envelope) != 10 || fields["FLAGS"].list == nil || fields["BODYSTRUCTURE"].list == nil {
		return MessageSummary{}, ErrProtocol
	}
	flags := make([]string, 0, len(fields["FLAGS"].list))
	for _, flag := range fields["FLAGS"].list {
		if flag.atom == "" || len(flag.atom) > 64 || strings.ContainsAny(flag.atom, "\x00\r\n ()") {
			return MessageSummary{}, ErrProtocol
		}
		flags = append(flags, flag.atom)
	}
	sender, err := envelopeSender(envelope[2])
	if err != nil {
		return MessageSummary{}, err
	}
	threadSource := envelope[9].atom
	if envelope[8].atom != "" {
		threadSource = envelope[8].atom
	}
	if !threaded || threadSource == "" {
		threadSource = folder + ":" + strconv.FormatUint(uint64(uidValidity), 10) + ":" + strconv.FormatUint(uidValue, 10)
	}
	threadHash := sha256.Sum256([]byte(threadSource))
	return MessageSummary{
		Identity: MessageIdentity{Folder: folder, UIDValidity: uidValidity, UID: uint32(uidValue)},
		ModSeq: modSeq, ThreadID: "thr_" + hex.EncodeToString(threadHash[:16]), Flags: flags,
		Sender: sender, Subject: boundedProjection(envelope[1].atom, 998), Date: date.UTC(), Size: size,
		HasAttachment: bodyHasAttachment(fields["BODYSTRUCTURE"]),
	}, nil
}

func envelopeSender(value imapValue) (Address, error) {
	if value.list == nil || len(value.list) == 0 {
		return Address{}, nil
	}
	if value.list[0].list == nil || len(value.list[0].list) != 4 {
		return Address{}, ErrProtocol
	}
	address := value.list[0].list
	if address[2].atom == "" || address[3].atom == "" {
		return Address{}, ErrProtocol
	}
	return Address{Name: boundedProjection(address[0].atom, 256), Mailbox: boundedProjection(address[2].atom, 64), Host: boundedProjection(address[3].atom, 255)}, nil
}

func boundedProjection(value string, maximum int) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	value = strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f || character >= 0x202a && character <= 0x202e || character >= 0x2066 && character <= 0x2069 {
			return ' '
		}
		return character
	}, value)
	runes := []rune(value)
	if len(runes) > maximum {
		return string(runes[:maximum])
	}
	return value
}

func bodyHasAttachment(value imapValue) bool {
	if strings.EqualFold(value.atom, "ATTACHMENT") || strings.EqualFold(value.atom, "FILENAME") || strings.EqualFold(value.atom, "NAME") {
		return true
	}
	for _, child := range value.list {
		if bodyHasAttachment(child) {
			return true
		}
	}
	return false
}

func (backend *DovecotBackend) Search(ctx context.Context, bearer string, request SearchRequest) (SearchPage, error) {
	if ctx == nil || !validMailboxName(request.Folder) || !request.Criteria.valid() || request.Limit == 0 || request.Limit > MaximumPageSize || !request.Sort.valid() || request.Cursor != "" {
		return SearchPage{}, ErrInvalid
	}
	client, err := backend.connect(ctx, bearer)
	if err != nil {
		return SearchPage{}, err
	}
	defer client.close()
	selected, err := selectMailbox(client, request.Folder)
	if err != nil {
		return SearchPage{}, err
	}
	if request.expectedUIDValidity != 0 && request.expectedUIDValidity != selected.UIDValidity {
		return SearchPage{}, ErrStaleUIDValidity
	}
	criteria, err := buildSearchCriteria(request.Criteria)
	if err != nil {
		return SearchPage{}, err
	}
	uids, more, err := boundedUIDSearch(client, request.Sort, request.afterUID, int(request.Limit)+1, criteria)
	if err != nil {
		return SearchPage{}, err
	}
	if len(uids) > int(request.Limit) {
		uids = uids[:request.Limit]
		more = true
	}
	page := SearchPage{Folder: request.Folder, UIDValidity: selected.UIDValidity, HighestModSeq: selected.HighestModSeq, more: more}
	for _, uid := range uids {
		page.Identities = append(page.Identities, MessageIdentity{Folder: request.Folder, UIDValidity: selected.UIDValidity, UID: uid})
	}
	if len(uids) > 0 {
		page.lastUID = uids[len(uids)-1]
	}
	return page, nil
}

func buildSearchCriteria(criteria SearchCriteria) (string, error) {
	if !criteria.valid() {
		return "", ErrInvalid
	}
	parts := make([]string, 0, MaximumSearchTerms)
	for _, value := range []struct{ key, text string }{{"TEXT", criteria.Text}, {"FROM", criteria.From}, {"SUBJECT", criteria.Subject}} {
		if value.text == "" {
			continue
		}
		quoted, err := imapQuote(value.text)
		if err != nil {
			return "", err
		}
		parts = append(parts, value.key+" "+quoted)
	}
	if !criteria.Since.IsZero() {
		parts = append(parts, "SINCE "+criteria.Since.UTC().Format("02-Jan-2006"))
	}
	if !criteria.Before.IsZero() {
		parts = append(parts, "BEFORE "+criteria.Before.UTC().Format("02-Jan-2006"))
	}
	if criteria.Seen != nil {
		if *criteria.Seen {
			parts = append(parts, "SEEN")
		} else {
			parts = append(parts, "UNSEEN")
		}
	}
	if criteria.Flagged != nil {
		if *criteria.Flagged {
			parts = append(parts, "FLAGGED")
		} else {
			parts = append(parts, "UNFLAGGED")
		}
	}
	if criteria.HasAttachment != nil {
		attachment := `HEADER Content-Disposition "attachment"`
		if !*criteria.HasAttachment {
			attachment = "NOT " + attachment
		}
		parts = append(parts, attachment)
	}
	return strings.Join(parts, " "), nil
}

var _ Backend = (*DovecotBackend)(nil)

type cachedImage struct {
	contentType string
	content     []byte
	expiresAt   time.Time
}

type HTTPRemoteImageProxy struct {
	resolver   *net.Resolver
	dialer     *net.Dialer
	maximumCacheBytes uint64
	cacheBytes uint64
	cache      map[string]cachedImage
	mutex      sync.Mutex
}

func NewHTTPRemoteImageProxy(resolver *net.Resolver, dialer *net.Dialer, maximumCacheBytes uint64) (*HTTPRemoteImageProxy, error) {
	if resolver == nil || dialer == nil || maximumCacheBytes < MaximumRemoteImageBytes || maximumCacheBytes > 512<<20 {
		return nil, ErrInvalid
	}
	return &HTTPRemoteImageProxy{resolver: resolver, dialer: dialer, maximumCacheBytes: maximumCacheBytes,
		cache: make(map[string]cachedImage)}, nil
}

func normalizeRemoteImageURL(raw string) (*url.URL, error) {
	if len(raw) == 0 || len(raw) > 4096 || strings.ContainsAny(raw, "\x00\r\n") {
		return nil, ErrInvalid
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" || parsed.Hostname() == "" ||
		parsed.Port() != "" && parsed.Port() != "443" {
		return nil, ErrInvalid
	}
	host := strings.ToLower(parsed.Hostname())
	if net.ParseIP(host) == nil {
		if len(host) > 253 {
			return nil, ErrInvalid
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, ErrInvalid
			}
			for _, character := range label {
				if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
					return nil, ErrInvalid
				}
			}
		}
	}
	parsed.Scheme = "https"
	parsed.Host = host
	if strings.Contains(host, ":") {
		parsed.Host = "[" + host + "]"
	}
	return parsed, nil
}

func validImageBytes(contentType string, content []byte) bool {
	if len(content) == 0 {
		return false
	}
	switch contentType {
	case "image/png":
		return len(content) >= 8 && bytes.Equal(content[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
	case "image/jpeg":
		return len(content) >= 3 && content[0] == 0xff && content[1] == 0xd8 && content[2] == 0xff
	case "image/gif":
		return len(content) >= 6 && (string(content[:6]) == "GIF87a" || string(content[:6]) == "GIF89a")
	case "image/webp":
		return len(content) >= 12 && string(content[:4]) == "RIFF" && string(content[8:12]) == "WEBP"
	case "image/avif":
		return len(content) >= 12 && string(content[4:8]) == "ftyp" && (string(content[8:12]) == "avif" || string(content[8:12]) == "avis")
	default:
		return false
	}
}

func publicRemoteIP(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	blocked := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	for _, prefix := range blocked {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func (proxy *HTTPRemoteImageProxy) resolvePublic(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if !publicRemoteIP(ip) {
			return nil, ErrUnauthorized
		}
		return ip, nil
	}
	addresses, err := proxy.resolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 || len(addresses) > 32 {
		return nil, ErrUnavailable
	}
	for _, address := range addresses {
		if !publicRemoteIP(address.IP) {
			return nil, ErrUnauthorized
		}
	}
	return addresses[0].IP, nil
}

func (proxy *HTTPRemoteImageProxy) cached(key string, now time.Time) (RemoteImage, bool) {
	proxy.mutex.Lock()
	defer proxy.mutex.Unlock()
	item, ok := proxy.cache[key]
	if !ok || !item.expiresAt.After(now) {
		if ok {
			proxy.cacheBytes -= uint64(len(item.content))
			delete(proxy.cache, key)
		}
		return RemoteImage{}, false
	}
	content := append([]byte(nil), item.content...)
	return RemoteImage{ContentType: item.contentType, Size: uint64(len(content)), Body: io.NopCloser(bytes.NewReader(content)),
		CacheKey: key, CacheUntil: item.expiresAt, FromCache: true, CacheControl: "private, no-store", ReferrerPolicy: "no-referrer"}, true
}

func (proxy *HTTPRemoteImageProxy) putCached(key, contentType string, content []byte, expiresAt time.Time) error {
	proxy.mutex.Lock()
	defer proxy.mutex.Unlock()
	if uint64(len(content)) > proxy.maximumCacheBytes {
		return ErrLimit
	}
	for existingKey, item := range proxy.cache {
		if !item.expiresAt.After(time.Now().UTC()) || proxy.cacheBytes+uint64(len(content)) > proxy.maximumCacheBytes {
			proxy.cacheBytes -= uint64(len(item.content))
			delete(proxy.cache, existingKey)
		}
	}
	if proxy.cacheBytes+uint64(len(content)) > proxy.maximumCacheBytes {
		return ErrLimit
	}
	if prior, ok := proxy.cache[key]; ok {
		proxy.cacheBytes -= uint64(len(prior.content))
	}
	proxy.cache[key] = cachedImage{contentType: contentType, content: append([]byte(nil), content...), expiresAt: expiresAt}
	proxy.cacheBytes += uint64(len(content))
	return nil
}

func (proxy *HTTPRemoteImageProxy) Fetch(ctx context.Context, request RemoteImageRequest) (RemoteImage, error) {
	if proxy == nil || proxy.resolver == nil || proxy.dialer == nil || ctx == nil || !opaqueIDPattern.MatchString(request.CachePartition) ||
		!validDigest(request.ExpectedDigest) || request.MaximumBytes == 0 || request.MaximumBytes > MaximumRemoteImageBytes {
		return RemoteImage{}, ErrInvalid
	}
	parsed, err := normalizeRemoteImageURL(request.URL)
	if err != nil {
		return RemoteImage{}, err
	}
	digest := sha256.Sum256([]byte(parsed.String()))
	if hex.EncodeToString(digest[:]) != request.ExpectedDigest {
		return RemoteImage{}, ErrUnauthorized
	}
	cacheKey := digestParts(request.CachePartition, request.ExpectedDigest)
	if image, ok := proxy.cached(cacheKey, time.Now().UTC()); ok {
		if image.Size > request.MaximumBytes {
			image.Body.Close()
			return RemoteImage{}, ErrLimit
		}
		return image, nil
	}
	current := parsed
	for redirect := 0; redirect <= MaximumRemoteImageRedirects; redirect++ {
		ip, resolveErr := proxy.resolvePublic(ctx, current.Hostname())
		if resolveErr != nil {
			return RemoteImage{}, resolveErr
		}
		transport := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: current.Hostname()},
			TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 32 << 10,
			DialContext: func(dialContext context.Context, network, _ string) (net.Conn, error) {
				return proxy.dialer.DialContext(dialContext, network, net.JoinHostPort(ip.String(), "443"))
			}}
		client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		httpRequest, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if requestErr != nil {
			transport.CloseIdleConnections()
			return RemoteImage{}, ErrInvalid
		}
		httpRequest.Header.Set("Accept", "image/avif,image/webp,image/png,image/jpeg,image/gif")
		httpRequest.Header.Set("User-Agent", "CyberPanel-RemoteImage/1")
		response, requestErr := client.Do(httpRequest)
		if requestErr != nil {
			transport.CloseIdleConnections()
			return RemoteImage{}, ErrUnavailable
		}
		if response.StatusCode >= 300 && response.StatusCode < 400 {
			location := response.Header.Get("Location")
			response.Body.Close()
			transport.CloseIdleConnections()
			if redirect == MaximumRemoteImageRedirects {
				return RemoteImage{}, ErrLimit
			}
			next, locationErr := current.Parse(location)
			if locationErr != nil {
				return RemoteImage{}, ErrInvalid
			}
			current, locationErr = normalizeRemoteImageURL(next.String())
			if locationErr != nil {
				return RemoteImage{}, locationErr
			}
			continue
		}
		if response.StatusCode != http.StatusOK || response.ContentLength > int64(request.MaximumBytes) || response.Header.Get("Content-Encoding") != "" {
			response.Body.Close()
			transport.CloseIdleConnections()
			return RemoteImage{}, ErrUnavailable
		}
		contentType, _, typeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		switch contentType {
		case "image/avif", "image/webp", "image/png", "image/jpeg", "image/gif":
		default:
			response.Body.Close()
			transport.CloseIdleConnections()
			return RemoteImage{}, errors.Join(ErrUnauthorized, typeErr)
		}
		content, readErr := io.ReadAll(io.LimitReader(response.Body, int64(request.MaximumBytes)+1))
		response.Body.Close()
		transport.CloseIdleConnections()
		if readErr != nil || uint64(len(content)) > request.MaximumBytes || !validImageBytes(contentType, content) {
			return RemoteImage{}, ErrLimit
		}
		expiresAt := time.Now().UTC().Add(time.Hour)
		if err = proxy.putCached(cacheKey, contentType, content, expiresAt); err != nil {
			return RemoteImage{}, err
		}
		return RemoteImage{ContentType: contentType, Size: uint64(len(content)), Body: io.NopCloser(bytes.NewReader(content)),
			CacheKey: cacheKey, CacheUntil: expiresAt, CacheControl: "private, no-store", ReferrerPolicy: "no-referrer"}, nil
	}
	return RemoteImage{}, ErrLimit
}

var _ RemoteImageProxy = (*HTTPRemoteImageProxy)(nil)

type LocalBlobStore struct {
	root string
	mutex sync.Mutex
}

type contextReader struct {
	ctx context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func NewLocalBlobStore(root string) (*LocalBlobStore, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return nil, ErrInvalid
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return nil, ErrUnauthorized
	}
	return &LocalBlobStore{root: root}, nil
}

func (store *LocalBlobStore) blobPath(owner BlobOwner, id string) (string, error) {
	if store == nil || !filepath.IsAbs(store.root) || !validOwner(owner) || !opaqueIDPattern.MatchString(id) {
		return "", ErrInvalid
	}
	return filepath.Join(store.root, digestParts(owner.TenantID, owner.UserID, owner.MailboxID, id)), nil
}

func (store *LocalBlobStore) admit(now time.Time, maximum uint64) error {
	directory, err := os.Open(store.root)
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(MaximumBlobStoreFiles + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	var count int
	var total uint64
	for _, entry := range entries {
		if len(entry.Name()) != 64 || !validDigest(entry.Name()) {
			return ErrUnauthorized
		}
		info, infoErr := entry.Info()
		if infoErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 0 {
			return ErrUnauthorized
		}
		if info.ModTime().Before(now.Add(-MaximumUploadLifetime - time.Hour)) {
			if removeErr := os.Remove(filepath.Join(store.root, entry.Name())); removeErr != nil {
				return removeErr
			}
			continue
		}
		count++
		if uint64(info.Size()) > MaximumBlobStoreBytes-total {
			return ErrLimit
		}
		total += uint64(info.Size())
	}
	if count >= MaximumBlobStoreFiles || maximum > MaximumBlobStoreBytes-total {
		return ErrLimit
	}
	return nil
}

func (store *LocalBlobStore) Put(ctx context.Context, blob BlobInfo, source io.Reader, maximum uint64) (BlobInfo, error) {
	if ctx == nil || source == nil || maximum == 0 || maximum > MaximumAttachmentBytes || blob.Size != 0 || blob.Digest != "" ||
		blob.Filename == "" || len(blob.Filename) > 255 || blob.ContentType == "" || len(blob.ContentType) > 127 || blob.ExpiresAt.IsZero() {
		return BlobInfo{}, ErrInvalid
	}
	path, err := store.blobPath(blob.Owner, blob.ID)
	if err != nil {
		return BlobInfo{}, err
	}
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if err = store.admit(time.Now().UTC(), maximum); err != nil {
		return BlobInfo{}, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return BlobInfo{}, errors.Join(ErrConflict, err)
	}
	committed := false
	defer func() {
		file.Close()
		if !committed {
			_ = os.Remove(path)
		}
	}()
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(&contextReader{ctx: ctx, reader: source}, int64(maximum)+1))
	if err != nil || written <= 0 || uint64(written) > maximum {
		return BlobInfo{}, errors.Join(ErrLimit, err)
	}
	if err = file.Sync(); err != nil {
		return BlobInfo{}, err
	}
	if err = file.Close(); err != nil {
		return BlobInfo{}, err
	}
	committed = true
	blob.Size = uint64(written)
	blob.Digest = hex.EncodeToString(hash.Sum(nil))
	return blob, nil
}

func (store *LocalBlobStore) Open(ctx context.Context, owner BlobOwner, id string) (io.ReadCloser, BlobInfo, error) {
	if ctx == nil {
		return nil, BlobInfo{}, ErrInvalid
	}
	path, err := store.blobPath(owner, id)
	if err != nil {
		return nil, BlobInfo{}, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, BlobInfo{}, ErrNotFound
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > MaximumAttachmentBytes {
		return nil, BlobInfo{}, ErrUnauthorized
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, BlobInfo{}, err
	}
	return file, BlobInfo{ID: id, Owner: owner, Size: uint64(info.Size())}, nil
}

func (store *LocalBlobStore) Delete(ctx context.Context, owner BlobOwner, id string) error {
	if ctx == nil {
		return ErrInvalid
	}
	path, err := store.blobPath(owner, id)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrUnauthorized
	}
	return os.Remove(path)
}

var _ BlobStore = (*LocalBlobStore)(nil)
