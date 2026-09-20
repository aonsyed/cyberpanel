package apiserver

import (
	"context"
	"net/http"
	"strings"
)

type MailboxPasswordEnrollment interface {
	EnrollMailboxPassword(context.Context, EdgeCall, []byte) (SecretReference, error)
}
type MailboxPasswordPayload struct {
	Password string `json:"password"`
}

func validateMailboxPassword(value any) error {
	password := value.(*MailboxPasswordPayload).Password
	if len(password) < 12 || len(password) > 1024 || strings.IndexByte(password, 0) >= 0 {
		return invalid("mailbox password must contain 12 to 1024 bytes without NUL")
	}
	return nil
}

func bindMailboxPassword(registry *Registry, service MailboxPasswordEnrollment) error {
	if service == nil {
		return nil
	}
	return registry.Bind("mail.mailbox.password.enroll", func(ctx context.Context, inv Invocation, value any) (OperationResult, error) {
		payload := value.(*MailboxPasswordPayload)
		password := []byte(payload.Password)
		payload.Password = ""
		defer clearSecret(password)
		reference, err := service.EnrollMailboxPassword(ctx, edgeCall(inv), password)
		if err != nil {
			return OperationResult{}, mapMailError(mapSecretError(err))
		}
		return OperationResult{Status: http.StatusCreated, Value: reference, Generation: reference.Version}, nil
	})
}
