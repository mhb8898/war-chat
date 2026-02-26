package server

import (
	"encoding/binary"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	hrtSendBufferSize  = 256
	hrtMaxFrameSize    = 256 << 10
	hrtBinaryHeaderMin = 7 // streamType(1) + flags(1) + toLen(1) + at least 1 byte to + payloadLen(4)
)

var hrtBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, hrtMaxFrameSize)
		return &b
	},
}

type hrtOut struct {
	data    []byte
	dataPtr *[]byte // for binary: pool pointer to Put after send (nil for text)
	binary  bool
}

type hrtClient struct {
	conn     *websocket.Conn
	username string
	roomId   string
	send     chan hrtOut
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
		send: make(chan hrtOut, hrtSendBufferSize),
		hub:  h,
	}

	go client.writePump()
	client.readPump()
}

func (c *hrtClient) writePump() {
	defer c.conn.Close()
	for out := range c.send {
		msgType := websocket.TextMessage
		if out.binary {
			msgType = websocket.BinaryMessage
		}
		if err := c.conn.WriteMessage(msgType, out.data); err != nil {
			break
		}
		if out.dataPtr != nil {
			*out.dataPtr = (*out.dataPtr)[:0]
			hrtBufPool.Put(out.dataPtr)
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
		messageType, message, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		if messageType == websocket.BinaryMessage {
			if c.username == "" {
				continue
			}
			if len(message) < hrtBinaryHeaderMin {
				continue
			}
			streamType := message[0]
			flags := message[1]
			toLen := int(message[2])
			if 3+toLen+4 > len(message) {
				continue
			}
			to := string(message[3 : 3+toLen])
			payloadLen := binary.LittleEndian.Uint32(message[3+toLen : 7+toLen])
			if int(payloadLen) > len(message)-7-toLen {
				continue
			}
			payload := message[7+toLen : 7+toLen+int(payloadLen)]
			fromBytes := []byte(c.username)
			fromLen := len(fromBytes)
			if fromLen > 255 {
				continue
			}
			need := 7 + fromLen + int(payloadLen)
			outPtr := hrtBufPool.Get().(*[]byte)
			*outPtr = (*outPtr)[:need]
			out := *outPtr
			out[0] = streamType
			out[1] = flags
			out[2] = byte(fromLen)
			copy(out[3:], fromBytes)
			binary.LittleEndian.PutUint32(out[3+fromLen:], uint32(payloadLen))
			copy(out[7+fromLen:], payload)
			c.hub.sendToPeerBinary(c.roomId, to, outPtr)
			continue
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
				}), nil, false)
			}

			c.hub.sendToClient(c, mustMarshal(map[string]interface{}{
				"type":     "joined",
				"roomId":   c.roomId,
				"username": c.username,
				"peers":    roomPeers,
			}), false)
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
			c.hub.sendToPeer(c.roomId, frame.To, data, nil, false)
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
			peerLeft := mustMarshal(map[string]interface{}{
				"type":     "peer_left",
				"username": c.username,
			})
			for _, cl := range room {
				select {
				case cl.send <- hrtOut{data: peerLeft, binary: false}:
				default:
					// drop if backpressured
				}
			}
		}
	}
	h.mu.Unlock()
	close(c.send)
}

func (h *HRTHub) sendToPeer(roomId, username string, data []byte, dataPtr *[]byte, binary bool) (sent bool) {
	h.mu.RLock()
	room := h.rooms[roomId]
	client := room[username]
	h.mu.RUnlock()

	if client != nil {
		select {
		case client.send <- hrtOut{data: data, dataPtr: dataPtr, binary: binary}:
			return true
		default:
			// backpressure: drop (e.g. audio/video)
		}
	}
	return false
}

func (h *HRTHub) sendToPeerBinary(roomId, username string, dataPtr *[]byte) {
	if !h.sendToPeer(roomId, username, *dataPtr, dataPtr, true) {
		*dataPtr = (*dataPtr)[:0]
		hrtBufPool.Put(dataPtr)
	}
}

func (h *HRTHub) sendToClient(c *hrtClient, data []byte, binary bool) {
	select {
	case c.send <- hrtOut{data: data, binary: binary}:
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
		case client.send <- hrtOut{data: data, binary: false}:
		default:
			// drop on backpressure
		}
	}
}

func mustMarshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}
