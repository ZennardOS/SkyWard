package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Auth struct {
	AccountID string
	Expires   time.Time
}

type TransportPacket struct {
	Version           uint8  `json:"version"`
	PacketID          string `json:"packet_id"`
	ReceiverAccountID string `json:"receiver_account_id"`
	PacketType        string `json:"packet_type"`
	Payload           string `json:"payload"`
}

const (
	PacketSize        = 256 * 1024 // 256 KB
	PacketsPerAccount = 1000
)

var (
	mutex   sync.Mutex
	packets = make(map[string][]TransportPacket)
	identy  = make(map[string]Auth)
)

func main() {
	http.HandleFunc("/packets", packetsHandler)
	http.HandleFunc("/packets/", packetHandler)
	http.HandleFunc("/auth/verification", HandlerAuth)
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

func HandlerAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	accountID := r.URL.Query().Get("account_id")
	if accountID == "" {
		http.Error(w, "account_id is required", http.StatusBadRequest)
		return
	}

	randomBytes := make([]byte, 32)

	if _, err := rand.Read(randomBytes); err != nil {
		http.Error(w, "failed to generate random number", http.StatusInternalServerError)
		return
	}

	numb := base64.StdEncoding.EncodeToString(randomBytes)
	mutex.Lock()

	identy[numb] = Auth{
		AccountID: accountID,
		Expires:   time.Now().Add(30 * time.Second),
	}

	mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")

	//json.NewEncoder(w).Encode(map[string]string {
	//	"Number" : numb,
	//	})
	jsonbytes, err := json.Marshal(map[string]string{"number": numb})
	if err != nil {
		http.Error(w, "failed to marshal json", http.StatusInternalServerError)
		return
	}
	w.Write(jsonbytes)

}

func authorize(accountID string, publicKey string, number string, signature string, r *http.Request) error {
	mutex.Lock()
	auth, exists := identy[number]
	if exists {
		delete(identy, number)
	}
	mutex.Unlock()

	if !exists {
		return fmt.Errorf("number not found!")
	}

	if time.Now().After(auth.Expires) {
		return fmt.Errorf("auth expired!")
	}

	if auth.AccountID != accountID {
		return fmt.Errorf("Account id doesn't match!")
	}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKey)

	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("Public key has wrong size!")
	}

	hash := sha256.Sum256(publicKeyBytes)
	expectedID := base64.StdEncoding.EncodeToString(hash[:16])

	if expectedID != accountID {
		return fmt.Errorf("Public key has wrong account id!")
	}

	signBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	authMessage := fmt.Sprintf("sky-relay-auth-v1\n%s\n%s\n%s", number, r.Method, r.URL.Path)

	if !ed25519.Verify(ed25519.PublicKey(publicKeyBytes), []byte(authMessage), signBytes) {
		return fmt.Errorf("invalid signature!")
	}

	return nil

}

func packetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	packetID := strings.TrimPrefix(r.URL.Path, "/packets/")
	accountID := r.URL.Query().Get("account_id")

	if packetID == "" || accountID == "" {
		http.Error(w, "packet_id and account_id is reqired", http.StatusBadRequest)
		return
	}

	publicKey := r.Header.Get("X-Public-Key")
	number := r.Header.Get("X-Number")
	sign := r.Header.Get("X-Signature")

	if err := authorize(accountID, publicKey, number, sign, r); err != nil {
		log.Println("DELETE auth failed: ", err)

		http.Error(w, "unauthorized", http.StatusUnauthorized)

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
		packets[accountID] = filtered
	}

	w.WriteHeader(http.StatusNoContent)
}

func handlePostPacket(w http.ResponseWriter, r *http.Request) {
	accountID := r.Header.Get("X-Account-ID")
	publicKey := r.Header.Get("X-Public-Key")
	numb := r.Header.Get("X-Number")
	sign := r.Header.Get("X-Signature")

	if err := authorize(accountID, publicKey, numb, sign, r); err != nil {
		log.Println("POST auth failed: ", err)

		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, PacketSize)

	var packet TransportPacket

	if err := json.NewDecoder(r.Body).Decode(&packet); err != nil {
		http.Error(w, "invalid json or too large packet", http.StatusBadRequest)
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

	if len(packet.PacketID) > 64 || len(packet.ReceiverAccountID) > 128 || len(packet.PacketType) > 32 {
		http.Error(w, "invalid packet field size", http.StatusBadRequest)
		return
	}
	mutex.Lock()
	queue := packets[packet.ReceiverAccountID]
	if len(queue) >= PacketsPerAccount {
		http.Error(w, "receiver queue is full", http.StatusTooManyRequests)
		return
	}

	packets[packet.ReceiverAccountID] = append(queue, packet)
	mutex.Unlock()

	w.WriteHeader(http.StatusCreated)
}

func handleGetPackets(w http.ResponseWriter, r *http.Request) {
	accountID := r.URL.Query().Get("account_id")

	publicKey := r.Header.Get("X-Public-Key")
	numb := r.Header.Get("X-Number")
	sign := r.Header.Get("X-Signature")

	if err := authorize(accountID, publicKey, numb, sign, r); err != nil {
		log.Println("auth is failed: ", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if accountID == "" {
		http.Error(w, "account_id required", http.StatusBadRequest)
		return
	}

	mutex.Lock()

	packet := packets[accountID]

	mutex.Unlock()
	if packet == nil {
		packet = []TransportPacket{}
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(packet); err != nil {
		http.Error(w, "failed to encode responce", http.StatusInternalServerError)
		return
	}

}
