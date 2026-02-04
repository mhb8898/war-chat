package protocol

// Client -> Server messages
type RegisterMsg struct {
	Type     string `json:"type"`
	Username string `json:"username"`
	PubKey   string `json:"pubkey"`
}

type AuthMsg struct {
	Type      string `json:"type"`
	Username  string `json:"username"`
	Signature string `json:"signature"`
}

type SendMsg struct {
	Type    string `json:"type"`
	To      string `json:"to"`
	Payload string `json:"payload"`
	Nonce   string `json:"nonce"`
}

type FetchKeysMsg struct {
	Type  string   `json:"type"`
	Users []string `json:"users"`
}

type DeliveredMsg struct {
	Type string   `json:"type"`
	IDs  []string `json:"ids"`
}

// Server -> Client messages
type OfflineMessagesMsg struct {
	Type     string          `json:"type"`
	Messages []OfflineMsg    `json:"messages"`
}

type OfflineMsg struct {
	ID      string `json:"id"`
	From    string `json:"from"`
	Payload string `json:"payload"`
	Nonce   string `json:"nonce"`
	Ts      int64  `json:"ts"`
}

type KeysResponseMsg struct {
	Type  string            `json:"type"`
	Keys  map[string]string `json:"keys"`
}

type ErrorMsg struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type IncomingMsg struct {
	Type    string `json:"type"`
	From    string `json:"from"`
	Payload string `json:"payload"`
	Nonce   string `json:"nonce"`
	Ts      int64  `json:"ts"`
	ID      string `json:"id"`
}
