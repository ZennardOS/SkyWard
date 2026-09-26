package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
)

type TransportPacket struct {
	Version           uint8  `json:"version"`
	PacketID          string `json:"packet_id"`
	ReceiverAccountID string `json:"receiver_account_id"`
	PacketType        string `json:"packet_type"`
	Payload           string `json:"payload"`
}

var (
	mutex   sync.Mutex
	packets = make(map[string][]TransportPacket)
)

func main() {
	http.HandleFunc("/packets", packetsHandler)
	http.HandleFunc("/packets/", packetHandler)
	log.Println("Sky relay listening on :8080")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

func packetsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handlePostPacket(w, r)
	case http.MethodGet:
		handleGetPackets(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func packetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	packetID := strings.TrimPrefix(r.URL.Path, "/packets/")
	accountID := r.URL.Query().Get("account_id");

	if packetID == "" || accountID == "" {
		http.Error(w, "packet_id and account_id is reqired", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	queue := packets[accountID]

	filtered := make([]TransportPacket, 0, len(queue))

	found := false

	for _, packet := range queue {
		if packet.PacketID == packetID {
			found = true
			continue
		}

		filtered = append(filtered, packet)
	}

	if !found {
		http.Error(w, "not found correct packets", http.StatusNotFound)
		return
	}

	if len(filtered) == 0 {
		delete(packets, accountID)
	} else {
		packets[packetID] = filtered
	}

	w.WriteHeader(http.StatusNoContent)
}

func handlePostPacket(w http.ResponseWriter, r *http.Request) {
	var packet TransportPacket

	if err := json.NewDecoder(r.Body).Decode(&packet); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if packet.Version != 1 {
		http.Error(w, "Unsupported version", http.StatusBadRequest)
		return
	}

	if packet.PacketID == "" || packet.ReceiverAccountID == "" || packet.PacketType == "" || packet.Payload == "" {
		http.Error(w, "invalid packet", http.StatusBadRequest)
		return
	}

	mutex.Lock()

	packets[packet.ReceiverAccountID] = append(packets[packet.ReceiverAccountID], packet)
	mutex.Unlock()

	w.WriteHeader(http.StatusCreated)
}

func handleGetPackets(w http.ResponseWriter, r *http.Request) {
	accountID := r.URL.Query().Get("account_id")

	if accountID == "" {
		http.Error(w, "account_id required", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	packet := packets[accountID]
	if packet == nil {
		packet = []TransportPacket{}
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(packet); err != nil {
		http.Error(w, "failed to encode responce", http.StatusInternalServerError)
		return
	}

}
