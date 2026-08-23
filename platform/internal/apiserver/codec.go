package apiserver

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strconv"
)

func decodeStrict(content []byte, target any) error {
	if len(content) == 0 { return invalid("empty JSON body") }
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil { return invalid("JSON body") }
	if err := decoder.Decode(&struct{}{}); err != io.EOF { return invalid("trailing JSON data") }
	return nil
}

func readJSON(request *http.Request, maximum int64, target any) error {
	if request == nil || request.Body == nil { return invalid("request body") }
	if maximum <= 0 { maximum = DefaultMaximumBodyBytes }
	if request.ContentLength > maximum { return invalid("request body is too large") }
	contentType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || contentType != ContentTypeJSON { return invalid("content type") }
	content, err := io.ReadAll(io.LimitReader(request.Body, maximum+1))
	if err != nil || int64(len(content)) > maximum { return invalid("request body is too large") }
	return decodeStrict(content, target)
}

func canonicalPayload(raw json.RawMessage, newValue func() any, validate func(any) error) (json.RawMessage, any, error) {
	if len(raw) == 0 { raw = json.RawMessage(`{}`) }
	value := newValue()
	if value == nil { return nil, nil, invalid("operation codec") }
	if err := decodeStrict(raw, value); err != nil { return nil, nil, err }
	if validate != nil { if err := validate(value); err != nil { return nil, nil, err } }
	canonical, err := json.Marshal(value)
	if err != nil { return nil, nil, invalid("operation payload") }
	return canonical, value, nil
}

func writeJSON(writer http.ResponseWriter, status int, value any, maximum int64) error {
	content, err := json.Marshal(value)
	if err != nil { return err }
	if maximum <= 0 { maximum = DefaultMaximumResponseBytes }
	if int64(len(content)) > maximum { return ErrResponseTooLarge }
	writer.Header().Set("Content-Type", ContentTypeJSON)
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_, err = writer.Write(content)
	return err
}

func writeProblem(writer http.ResponseWriter, problem Problem, maximum int64) {
	content, err := json.Marshal(problem)
	if err != nil || int64(len(content)) > maximum { content = []byte(`{"type":"https://cyberpanel.dev/problems/internal","title":"Internal error","status":500,"code":"internal_error"}`); problem.Status = http.StatusInternalServerError }
	writer.Header().Set("Content-Type", ContentTypeProblem)
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if problem.RetryAfterSeconds != 0 { writer.Header().Set("Retry-After", strconv.FormatUint(uint64(problem.RetryAfterSeconds),10)) }
	writer.WriteHeader(problem.Status)
	_, _ = writer.Write(content)
}
