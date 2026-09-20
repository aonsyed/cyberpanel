//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/aonsyed/cyberpanel/platform/internal/apiserver"
	"github.com/aonsyed/cyberpanel/platform/internal/identity"
	"github.com/aonsyed/cyberpanel/platform/internal/mail"
	"github.com/aonsyed/cyberpanel/platform/internal/secrets"
)

type mailboxPasswordEnrollment struct {
	store   mail.ControlRepository
	broker  *secrets.ManagementClient
	release string
	slots   chan struct{}
}

func (service *mailboxPasswordEnrollment) EnrollMailboxPassword(ctx context.Context, call apiserver.EdgeCall, password []byte) (apiserver.SecretReference, error) {
	defer wipeBytes(password)
	if ctx == nil || service == nil || service.store == nil || service.broker == nil || service.slots == nil || call.Assurance < identity.AssuranceMFA || call.TenantID == "" || call.ResourceID == "" || call.CommandID == "" || call.PrincipalID == "" || call.ExpectedGeneration == 0 {
		return apiserver.SecretReference{}, mail.ErrUnauthorized
	}
	resource, found, err := service.store.Load(ctx, call.TenantID, mail.ResourceMailbox, call.ResourceID)
	if err != nil {
		return apiserver.SecretReference{}, err
	}
	if !found {
		return apiserver.SecretReference{}, mail.ErrNotFound
	}
	if resource.TenantID != call.TenantID || resource.ID != call.ResourceID || resource.State != mail.StateActive || resource.Generation != call.ExpectedGeneration {
		return apiserver.SecretReference{}, mail.ErrConflict
	}
	var mailbox mail.Mailbox
	if json.Unmarshal(resource.Spec, &mailbox) != nil || string(mailbox.ID) != call.ResourceID {
		return apiserver.SecretReference{}, mail.ErrInvalidReceipt
	}
	domain, found, err := service.store.Load(ctx, call.TenantID, mail.ResourceDomain, string(mailbox.Domain))
	if err != nil {
		return apiserver.SecretReference{}, err
	}
	if !found || domain.State != mail.StateActive || domain.TenantID != call.TenantID {
		return apiserver.SecretReference{}, mail.ErrUnauthorized
	}
	owner, audience, err := mail.MailboxCredentialAudience(call.TenantID, mailbox.Domain, mailbox.ID, service.release)
	if err != nil {
		return apiserver.SecretReference{}, err
	}
	audience.ResourceKind = "mailbox_argon2id"
	command := sha256.Sum256([]byte("mailbox-password\x00" + call.TenantID + "\x00" + call.ResourceID + "\x00" + call.CommandID))
	identifier := secrets.ID("mailpw_" + hex.EncodeToString(command[:])[:48])
	salt := sha256.Sum256([]byte("mailbox-password-salt\x00" + identifier.String()))
	select {
	case service.slots <- struct{}{}:
		defer func() { <-service.slots }()
	case <-ctx.Done():
		return apiserver.SecretReference{}, ctx.Err()
	}
	hash, err := mail.HashMailboxPassword(password, salt[:16])
	if err != nil {
		return apiserver.SecretReference{}, err
	}
	defer wipeBytes(hash)
	metadata, err := service.broker.PutExact(ctx, secrets.PutRequest{ID: identifier, OwnerTenantID: owner, Purpose: secrets.PurposeAuthentication, Audience: audience, Plaintext: hash})
	if err != nil {
		return apiserver.SecretReference{}, err
	}
	return secretReference(metadata), nil
}
