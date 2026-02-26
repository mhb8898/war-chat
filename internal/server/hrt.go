package server

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	hrtSendBufferSize = 64
	hrtMaxFrameSize   = 64 << 10
)

type hrtClient struct {
	conn     *websocket.Conn
	username string
	roomId   string
	send     chan []byte
	hub      *HRTHub
}

type HRTHub struct {
	mu    sync.RWMutex
	rooms map[string]map[string]*hrtClient // roomId -> username -> client
	store *Store
}

func NewHRTHub(store *Store) *HRTHub {
	return &HRTHub{
		rooms: make(map[string]map[string]*hrtClient),
		store: store,
	}
}

func (h *HRTHub) ServeWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	client := &hrtClient{
		conn: conn,
		send: make(chan []byte, hrtSendBufferSize),
		hub:  h,
	}

	go client.writePump()
	client.readPump()
}

func (c *hrtClient) writePump() {
	defer c.conn.Close()
	for data := range c.send {
		if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
			break
		}
	}
}

func (c *hrtClient) readPump() {
	defer func() {
		c.hub.removeClient(c)
		c.conn.Close()
	}()

	c.conn.SetReadLimit(hrtMaxFrameSize)
	_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
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
		if err := json.Unmarshal(message, &base); err != nil {
			continue
		}

		if c.username == "" {
			// First message must be join
			if base.Type != "join" {
				continue
			}
			var join struct {
				RoomId   string `json:"roomId"`
				Username string `json:"username"`
			}
			if err := json.Unmarshal(message, &join); err != nil || join.RoomId == "" || join.Username == "" {
				continue
			}
			// Optional: verify username is registered
			if _, ok := c.hub.store.GetPubKey(join.Username); !ok {
				continue
			}
			c.username = join.Username
			c.roomId = join.RoomId
			c.hub.mu.Lock()
			if c.hub.rooms[c.roomId] == nil {
				c.hub.rooms[c.roomId] = make(map[string]*hrtClient)
			}
			c.hub.rooms[c.roomId][c.username] = c
			roomPeers := make([]string, 0, len(c.hub.rooms[c.roomId]))
			for u := range c.hub.rooms[c.roomId] {
				if u != c.username {
					roomPeers = append(roomPeers, u)
				}
			}
			c.hub.mu.Unlock()

			for _, peer := range roomPeers {
				c.hub.sendToPeer(c.roomId, peer, mustMarshal(map[string]interface{}{
					"type":     "peer_joined",
					"username": c.username,
				}))
			}

			c.hub.sendToClient(c, mustMarshal(map[string]interface{}{
				"type":     "joined",
				"roomId":   c.roomId,
				"username": c.username,
				"peers":    roomPeers,
			}))
			continue
		}

		// Forward frame: parse only routing envelope; keep payload as raw to avoid re-encoding (lower latency)
		var frame struct {
			To         string          `json:"to"`
			Stream     string          `json:"stream"`
			IsKeyframe bool            `json:"isKeyframe"`
			Payload    json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(message, &frame); err != nil || frame.To == "" {
			continue
		}

		out := struct {
			Type       string          `json:"type"`
			From       string          `json:"from"`
			To         string          `json:"to"`
			Stream     string          `json:"stream"`
			IsKeyframe bool            `json:"isKeyframe"`
			Payload    json.RawMessage `json:"payload"`
		}{
			Type: "frame", From: c.username, To: frame.To,
			Stream: frame.Stream, IsKeyframe: frame.IsKeyframe, Payload: frame.Payload,
		}
		data := mustMarshal(out)

		if frame.To == "*" {
			c.hub.broadcastInRoom(c.roomId, c.username, data)
		} else {
			c.hub.sendToPeer(c.roomId, frame.To, data)
		}
	}
}

func (h *HRTHub) removeClient(c *hrtClient) {
	if c.username == "" || c.roomId == "" {
		return
	}
	h.mu.Lock()
	if room, ok := h.rooms[c.roomId]; ok {
		delete(room, c.username)
		if len(room) == 0 {
			delete(h.rooms, c.roomId)
		} else {
			close(c.send)
			peerLeft := mustMarshal(map[string]interface{}{
				"type":     "peer_left",
				"username": c.username,
			})
			for _, client := range room {
				select {
				case client.send <- peerLeft:
				default:
					// drop if backpressured
				}
			}
		}
	}
	h.mu.Unlock()
}

func (h *HRTHub) sendToPeer(roomId, username string, data []byte) {
	h.mu.RLock()
	room := h.rooms[roomId]
	client := room[username]
	h.mu.RUnlock()

	if client != nil {
		select {
		case client.send <- data:
		default:
			// backpressure: drop (e.g. audio/video)
		}
	}
}

func (h *HRTHub) sendToClient(c *hrtClient, data []byte) {
	select {
	case c.send <- data:
	default:
	}
}

func (h *HRTHub) broadcastInRoom(roomId, exceptUsername string, data []byte) {
	h.mu.RLock()
	room := h.rooms[roomId]
	h.mu.RUnlock()

	if room == nil {
		return
	}
	for u, client := range room {
		if u == exceptUsername {
			continue
		}
		select {
		case client.send <- data:
		default:
			// drop on backpressure
		}
	}
}

func mustMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}
