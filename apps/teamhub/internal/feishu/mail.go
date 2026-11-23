package feishu

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// MailAddress is one address of a message.
type MailAddress struct {
	MailAddress string `json:"mail_address"`
	Name        string `json:"name"`
}

// MailAttachment describes one attachment of a received message.
type MailAttachment struct {
	ID             string `json:"id"`
	Filename       string `json:"filename"`
	AttachmentType int    `json:"attachment_type"`
	IsInline       bool   `json:"is_inline"`
	CID            string `json:"cid"`
}

// MailMessage is a message as the mail API returns it. Bodies and raw are
// base64url; InternalDate is epoch milliseconds.
type MailMessage struct {
	MessageID     string           `json:"message_id"`
	ThreadID      string           `json:"thread_id"`
	SMTPMessageID string           `json:"smtp_message_id"`
	Subject       string           `json:"subject"`
	HeadFrom      MailAddress      `json:"head_from"`
	To            []MailAddress    `json:"to"`
	Cc            []MailAddress    `json:"cc"`
	Bcc           []MailAddress    `json:"bcc"`
	BodyHTML      string           `json:"body_html"`
	BodyPlainText string           `json:"body_plain_text"`
	BodyPreview   string           `json:"body_preview"`
	InternalDate  string           `json:"internal_date"`
	MessageState  int              `json:"message_state"`
	InReplyTo     string           `json:"in_reply_to"`
	References    string           `json:"references"`
	ReplyTo       string           `json:"reply_to"`
	FolderID      string           `json:"folder_id"`
	LabelIDs      []string         `json:"label_ids"`
	Attachments   []MailAttachment `json:"attachments"`
	Raw           string           `json:"raw"`
}

// System folders and labels of a Feishu mailbox.
const (
	FolderInbox    = "INBOX"
	FolderSent     = "SENT"
	FolderArchived = "ARCHIVED"
	LabelUnread    = "UNREAD"
)

// ErrSendDisabled reports a draft send Feishu accepted but did not perform,
// such as one its automation policy blocks: nothing was sent.
var ErrSendDisabled = errors.New("Feishu did not send the draft")

// MaxAttachmentBytes bounds one attachment TeamHub downloads for an Agent.
const MaxAttachmentBytes = 25 << 20

func (c *Client) mailURL(region Region, path string, query url.Values) string {
	endpoint := c.endpoints(region).open + "/open-apis/mail/v1/user_mailboxes/me/" + path
	if len(query) > 0 {
		endpoint += "?" + query.Encode()
	}
	return endpoint
}

// ListMessageIDs lists one folder newest first, as message IDs.
func (c *Client) ListMessageIDs(ctx context.Context, region Region, accessToken, folderID string, onlyUnread bool, pageSize int, pageToken string) ([]string, string, error) {
	query := url.Values{"page_size": {strconv.Itoa(pageSize)}, "folder_id": {folderID}}
	if onlyUnread {
		query.Set("only_unread", "true")
	}
	if pageToken != "" {
		query.Set("page_token", pageToken)
	}
	var response struct {
		Data struct {
			Items     []string `json:"items"`
			HasMore   bool     `json:"has_more"`
			PageToken string   `json:"page_token"`
		} `json:"data"`
	}
	if err := c.call(ctx, "message list", http.MethodGet, c.mailURL(region, "messages", query), accessToken, nil, &response); err != nil {
		return nil, "", err
	}
	return response.Data.Items, nextToken(response.Data.HasMore, response.Data.PageToken), nil
}

// SearchMessageIDs searches the mailbox; folder is a lowercase folder name or
// empty for every folder.
func (c *Client) SearchMessageIDs(ctx context.Context, region Region, accessToken, text, folder string, onlyUnread bool, pageSize int, pageToken string) ([]string, string, error) {
	query := url.Values{"page_size": {strconv.Itoa(pageSize)}}
	if pageToken != "" {
		query.Set("page_token", pageToken)
	}
	filter := map[string]any{}
	if folder != "" {
		filter["folder"] = []string{folder}
	}
	if onlyUnread {
		filter["is_unread"] = true
	}
	var response struct {
		Data struct {
			Items []struct {
				MetaData struct {
					MessageBizID string `json:"message_biz_id"`
				} `json:"meta_data"`
			} `json:"items"`
			HasMore   bool   `json:"has_more"`
			PageToken string `json:"page_token"`
		} `json:"data"`
	}
	if err := c.call(ctx, "message search", http.MethodPost, c.mailURL(region, "search", query), accessToken, map[string]any{"query": text, "filter": filter}, &response); err != nil {
		return nil, "", err
	}
	ids := make([]string, 0, len(response.Data.Items))
	for _, item := range response.Data.Items {
		if item.MetaData.MessageBizID != "" {
			ids = append(ids, item.MetaData.MessageBizID)
		}
	}
	return ids, nextToken(response.Data.HasMore, response.Data.PageToken), nil
}

// BatchGetMessages reads up to 20 messages in format, in the order of ids;
// Feishu returns them in any order.
func (c *Client) BatchGetMessages(ctx context.Context, region Region, accessToken string, ids []string, format string) ([]MailMessage, error) {
	if len(ids) == 0 {
		return []MailMessage{}, nil
	}
	var response struct {
		Data struct {
			Messages []MailMessage `json:"messages"`
		} `json:"data"`
	}
	if err := c.call(ctx, "message batch read", http.MethodPost, c.mailURL(region, "messages/batch_get", nil), accessToken, map[string]any{"format": format, "message_ids": ids}, &response); err != nil {
		return nil, err
	}
	byID := make(map[string]MailMessage, len(response.Data.Messages))
	for _, message := range response.Data.Messages {
		byID[message.MessageID] = message
	}
	ordered := make([]MailMessage, 0, len(ids))
	for _, id := range ids {
		if message, ok := byID[id]; ok {
			ordered = append(ordered, message)
		}
	}
	return ordered, nil
}

// GetMessage reads one message with its bodies.
func (c *Client) GetMessage(ctx context.Context, region Region, accessToken, messageID string) (MailMessage, error) {
	var response struct {
		Data struct {
			Message MailMessage `json:"message"`
		} `json:"data"`
	}
	err := c.call(ctx, "message read", http.MethodGet, c.mailURL(region, "messages/"+url.PathEscape(messageID), url.Values{"format": {"full"}}), accessToken, nil, &response)
	return response.Data.Message, err
}

// ThreadMessages reads every message of a thread with its bodies.
func (c *Client) ThreadMessages(ctx context.Context, region Region, accessToken, threadID string) ([]MailMessage, error) {
	var response struct {
		Data struct {
			Thread struct {
				Messages []MailMessage `json:"messages"`
			} `json:"thread"`
		} `json:"data"`
	}
	err := c.call(ctx, "thread read", http.MethodGet, c.mailURL(region, "threads/"+url.PathEscape(threadID), url.Values{"format": {"full"}}), accessToken, nil, &response)
	return response.Data.Thread.Messages, err
}

// DownloadAttachment returns one attachment's bytes. Feishu hands out a
// presigned URL, fetched without the user's token.
func (c *Client) DownloadAttachment(ctx context.Context, region Region, accessToken, messageID, attachmentID string) ([]byte, error) {
	var response struct {
		Data struct {
			DownloadURLs []struct {
				AttachmentID string `json:"attachment_id"`
				DownloadURL  string `json:"download_url"`
			} `json:"download_urls"`
		} `json:"data"`
	}
	path := "messages/" + url.PathEscape(messageID) + "/attachments/download_url"
	if err := c.call(ctx, "attachment link", http.MethodGet, c.mailURL(region, path, url.Values{"attachment_ids": {attachmentID}}), accessToken, nil, &response); err != nil {
		return nil, err
	}
	link := ""
	for _, item := range response.Data.DownloadURLs {
		if item.AttachmentID == attachmentID {
			link = item.DownloadURL
		}
	}
	parsed, err := url.Parse(link)
	// Tests serve the link from a plain-HTTP fake Open Platform.
	if link == "" || err != nil || parsed.Scheme != "https" && c.baseURL == "" {
		return nil, errors.New("Feishu returned no usable attachment link")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return nil, err
	}
	response2, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}
	defer response2.Body.Close()
	if response2.StatusCode != http.StatusOK {
		return nil, &APIError{Operation: "attachment download", HTTPStatus: response2.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(response2.Body, MaxAttachmentBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxAttachmentBytes {
		return nil, ErrAttachmentTooLarge
	}
	return data, nil
}

// ErrAttachmentTooLarge reports an attachment over MaxAttachmentBytes.
var ErrAttachmentTooLarge = errors.New("the Feishu attachment exceeds the download limit")

type draftResponse struct {
	Data struct {
		Draft struct {
			ID      string      `json:"id"`
			Message MailMessage `json:"message"`
		} `json:"draft"`
	} `json:"data"`
}

// CreateDraft saves raw, a whole RFC 5322 message, as a new draft.
func (c *Client) CreateDraft(ctx context.Context, region Region, accessToken string, raw []byte) (string, error) {
	var response draftResponse
	if err := c.call(ctx, "draft create", http.MethodPost, c.mailURL(region, "drafts", nil), accessToken, map[string]string{"raw": base64.URLEncoding.EncodeToString(raw)}, &response); err != nil {
		return "", err
	}
	if response.Data.Draft.ID == "" {
		return "", errors.New("Feishu returned no draft ID")
	}
	return response.Data.Draft.ID, nil
}

// UpdateDraft replaces the whole draft with raw.
func (c *Client) UpdateDraft(ctx context.Context, region Region, accessToken, draftID string, raw []byte) error {
	return c.call(ctx, "draft update", http.MethodPut, c.mailURL(region, "drafts/"+url.PathEscape(draftID), nil), accessToken, map[string]string{"raw": base64.URLEncoding.EncodeToString(raw)}, nil)
}

// GetDraft reads a draft as its whole message, and its message ID.
func (c *Client) GetDraft(ctx context.Context, region Region, accessToken, draftID string) ([]byte, string, error) {
	var response draftResponse
	if err := c.call(ctx, "draft read", http.MethodGet, c.mailURL(region, "drafts/"+url.PathEscape(draftID), url.Values{"format": {"raw"}}), accessToken, nil, &response); err != nil {
		return nil, "", err
	}
	raw, err := DecodeBase64URL(response.Data.Draft.Message.Raw)
	if err != nil || len(raw) == 0 {
		return nil, "", errors.New("Feishu returned no readable draft")
	}
	return raw, response.Data.Draft.Message.MessageID, nil
}

// SendDraft sends a draft now and returns the sent message's IDs.
func (c *Client) SendDraft(ctx context.Context, region Region, accessToken, draftID string) (string, string, error) {
	var response struct {
		Data struct {
			MessageID             string `json:"message_id"`
			ThreadID              string `json:"thread_id"`
			AutomationSendDisable *struct {
				Reason string `json:"reason"`
			} `json:"automation_send_disable"`
		} `json:"data"`
	}
	if err := c.call(ctx, "draft send", http.MethodPost, c.mailURL(region, "drafts/"+url.PathEscape(draftID)+"/send", nil), accessToken, map[string]any{}, &response); err != nil {
		return "", "", err
	}
	if disabled := response.Data.AutomationSendDisable; disabled != nil {
		return "", "", fmt.Errorf("%w: %s", ErrSendDisabled, disabled.Reason)
	}
	return response.Data.MessageID, response.Data.ThreadID, nil
}

// MoveMessages moves messages to a folder, such as FolderArchived.
func (c *Client) MoveMessages(ctx context.Context, region Region, accessToken string, messageIDs []string, folderID string) error {
	return c.call(ctx, "message move", http.MethodPost, c.mailURL(region, "messages/batch_modify", nil), accessToken, map[string]any{"message_ids": messageIDs, "add_folder": folderID}, nil)
}

// DecodeBase64URL decodes the base64url Feishu uses, with or without padding.
func DecodeBase64URL(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if decoded, err := base64.URLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(value, "="))
}

func nextToken(hasMore bool, token string) string {
	if !hasMore {
		return ""
	}
	return token
}
