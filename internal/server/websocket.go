package server

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Client struct {
	conn     *websocket.Conn
	username string
	send     chan []byte
	hub      *Hub
}

type Hub struct {
	mu        sync.RWMutex
	clients   map[string]map[*Client]struct{}
	store     *Store
	broadcast chan *broadcastMsg
}

type broadcastMsg struct {
	recipient string
	data      []byte
}

func NewHub(store *Store) *Hub {
	return &Hub{
		clients:   make(map[string]map[*Client]struct{}),
		store:     store,
		broadcast: make(chan *broadcastMsg, 256),
	}
}

func (h *Hub) Run() {
	for msg := range h.broadcast {
		h.mu.RLock()
		clients := h.clients[msg.recipient]
		h.mu.RUnlock()

		if len(clients) > 0 {
			for c := range clients {
				select {
				case c.send <- msg.data:
				default:
					close(c.send)
					h.mu.Lock()
					delete(h.clients[c.username], c)
					if len(h.clients[c.username]) == 0 {
						delete(h.clients, c.username)
					}
					h.mu.Unlock()
				}
			}
		} else {
			// Recipient offline - message will be queued by the handler
			// This path is for real-time relay; offline is handled in ServeWS
		}
	}
}

func (h *Hub) IsOnline(username string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.clients[username]
	return ok
}

func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request, store *Store) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	client := &Client{
		conn: conn,
		send: make(chan []byte, 256),
		hub:  h,
	}

	go client.writePump()
	client.readPump(store)
}

func (c *Client) readPump(store *Store) {
	defer func() {
		c.hub.mu.Lock()
		if c.username != "" {
			if clients, ok := c.hub.clients[c.username]; ok {
				delete(clients, c)
				if len(clients) == 0 {
					delete(c.hub.clients, c.username)
				}
			}
		}
		c.hub.mu.Unlock()
		c.conn.Close()
	}()

	c.conn.SetReadLimit(64 << 10)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			break
		}

		var base struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(message, &base) != nil {
			continue
		}

		switch base.Type {
		case "register":
			var m struct {
				Username string `json:"username"`
				PubKey   string `json:"pubkey"`
			}
			if json.Unmarshal(message, &m) == nil && m.Username != "" && m.PubKey != "" {
				store.Register(m.Username, m.PubKey)
				c.username = m.Username

				c.hub.mu.Lock()
				if c.hub.clients[c.username] == nil {
					c.hub.clients[c.username] = make(map[*Client]struct{})
				}
				c.hub.clients[c.username][c] = struct{}{}
				c.hub.mu.Unlock()

				// Send offline messages
				offline, _ := store.GetOffline(c.username)
				if len(offline) > 0 {
					msgs := make([]map[string]interface{}, len(offline))
					copy(msgs, offline)
					resp, _ := json.Marshal(map[string]interface{}{
						"type":     "offline_messages",
						"messages": msgs,
					})
					select {
					case c.send <- resp:
					default:
					}
				}
			}
		case "send":
			var m struct {
				To      string `json:"to"`
				Payload string `json:"payload"`
				Nonce   string `json:"nonce"`
			}
			if json.Unmarshal(message, &m) != nil || m.To == "" || c.username == "" {
				continue
			}
			// Skip self-messages (Saved Messages are handled client-side only)
			if m.To == c.username {
				continue
			}

			msgID := uuid.New().String()
			ts := time.Now().UnixMilli()

			incoming := map[string]interface{}{
				"type":    "incoming",
				"id":     msgID,
				"from":   c.username,
				"payload": m.Payload,
				"nonce":  m.Nonce,
				"ts":     ts,
			}
			data, _ := json.Marshal(incoming)

			if c.hub.IsOnline(m.To) {
				c.hub.broadcast <- &broadcastMsg{recipient: m.To, data: data}
			} else {
				store.QueueOffline(m.To, msgID, c.username, m.Payload, m.Nonce, ts)
			}
		case "delivered":
			var m struct {
				IDs []string `json:"ids"`
			}
			if json.Unmarshal(message, &m) == nil && c.username != "" && len(m.IDs) > 0 {
				store.DeleteOffline(c.username, m.IDs)
			}
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
