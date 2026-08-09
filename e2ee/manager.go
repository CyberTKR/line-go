package e2ee

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/CyberTKR/line-go/protocol"
	"github.com/CyberTKR/line-go/service"
	"github.com/CyberTKR/line-go/storage"
)

const (
	cacheTTL       = 5 * time.Minute
	negotiationTTL = time.Minute
)

type timedKey struct {
	expires time.Time
	key     []byte
}

type negotiatedKey struct {
	expires time.Time
	id      int32
	key     []byte
	version int32
}

type Manager struct {
	session storage.Session
	talk    *service.Talk
	mu      sync.RWMutex
	keys    []map[int16]any
	public  map[string]timedKey
	direct  map[string]negotiatedKey
	group   map[string]negotiatedKey
}

type Message struct {
	To          string
	From        string
	ToType      int32
	ContentType int32
	Metadata    map[any]any
	Chunks      []any
}

func New(session storage.Session, talk *service.Talk) *Manager {
	return &Manager{
		session: session, talk: talk, public: make(map[string]timedKey),
		direct: make(map[string]negotiatedKey), group: make(map[string]negotiatedKey),
	}
}

func (m *Manager) ValidateKeychain() error {
	_, err := m.ownKey(0)
	return err
}

func (m *Manager) SyncSelfKey(ctx context.Context) (storage.DeviceKey, bool, error) {
	negotiated, err := m.negotiate(ctx, m.session.MID)
	if err != nil {
		return storage.DeviceKey{}, false, err
	}
	if _, err := m.ownKey(negotiated.id); err == nil {
		return storage.DeviceKey{}, false, nil
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return storage.DeviceKey{}, false, err
	}
	publicBytes := privateKey.PublicKey().Bytes()
	result, err := m.talk.RegisterE2EEPublicKey(ctx, m.session.AccessToken, publicBytes)
	if err != nil {
		return storage.DeviceKey{}, false, err
	}
	fields, ok := result.(map[int16]any)
	if !ok {
		return storage.DeviceKey{}, false, fmt.Errorf("registerE2EEPublicKey result is invalid: %T", result)
	}
	keyID := int32Field(fields, 2)
	if keyID == 0 {
		return storage.DeviceKey{}, false, fmt.Errorf("registerE2EEPublicKey returned an empty key ID")
	}
	key := storage.DeviceKey{
		KeyID: keyID, Version: 1,
		PrivateKey: base64.StdEncoding.EncodeToString(privateKey.Bytes()),
		PublicKey:  base64.StdEncoding.EncodeToString(publicBytes),
	}
	m.mu.Lock()
	m.session.DeviceKeys = append(m.session.DeviceKeys, key)
	m.keys = nil
	delete(m.direct, m.session.MID)
	m.mu.Unlock()
	return key, true, nil
}

func (m *Manager) EncryptText(ctx context.Context, to, text string) (string, map[string]string, [][]byte, error) {
	if m.session.MID == "" {
		return "", nil, nil, fmt.Errorf("account MID was not found for E2EE")
	}
	ownKey, err := m.ownKey(0)
	if err != nil {
		return "", nil, nil, err
	}
	senderKeyID := int32Field(ownKey, 2)
	var receiverKeyID, version int32
	var secret []byte
	if len(to) > 0 && (to[0] == 'u' || to[0] == 'U') {
		negotiated, err := m.negotiate(ctx, to)
		if err != nil {
			return "", nil, nil, err
		}
		receiverKeyID, version = negotiated.id, negotiated.version
		secret, err = x25519(bytesField(ownKey, 5), negotiated.key)
		if err != nil {
			return "", nil, nil, err
		}
	} else {
		group, err := m.groupKey(ctx, to)
		if err != nil {
			return "", nil, nil, err
		}
		receiverKeyID, version = group.id, group.version
		secret, err = x25519(group.key, bytesField(ownKey, 4))
		if err != nil {
			return "", nil, nil, err
		}
	}
	if version != 2 {
		return "", nil, nil, fmt.Errorf("unsupported E2EE message version: %d", version)
	}
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return "", nil, nil, err
	}
	binary.BigEndian.PutUint64(nonce[:8], uint64(time.Now().UnixMilli()))
	if _, err := rand.Read(nonce[8:]); err != nil {
		return "", nil, nil, err
	}
	key := sha256.Sum256(join(secret, salt, []byte("Key")))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, nil, err
	}
	aad := messageAAD(to, m.session.MID, senderKeyID, receiverKeyID, version, 0)
	plaintext, _ := json.Marshal(map[string]string{"text": text})
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return m.session.MID, map[string]string{"e2eeVersion": "2"}, [][]byte{
		salt, ciphertext, nonce, int32Bytes(senderKeyID), int32Bytes(receiverKeyID),
	}, nil
}

func (m *Manager) DecryptText(ctx context.Context, message Message) (string, error) {
	if message.To == "" || message.From == "" || len(message.Chunks) < 5 {
		return "", fmt.Errorf("E2EE message fields are missing")
	}
	chunks := make([][]byte, len(message.Chunks))
	for index, chunk := range message.Chunks {
		chunks[index] = chunkBytes(chunk)
	}
	if len(chunks[3]) != 4 || len(chunks[4]) != 4 {
		return "", fmt.Errorf("E2EE key ID chunk is invalid")
	}
	senderKeyID := int32(binary.BigEndian.Uint32(chunks[3]))
	receiverKeyID := int32(binary.BigEndian.Uint32(chunks[4]))
	version := int32(2)
	if rawVersion := metadataString(message.Metadata, "e2eeVersion"); rawVersion != "" {
		if parsed, err := strconv.ParseInt(rawVersion, 10, 32); err == nil {
			version = int32(parsed)
		}
	}
	var shared []byte
	if message.ToType == 0 || message.To[0] == 'u' || message.To[0] == 'U' {
		isSelf := message.From == m.session.MID
		ownKeyID, peerMID, peerKeyID := receiverKeyID, message.From, senderKeyID
		if isSelf {
			ownKeyID, peerMID, peerKeyID = senderKeyID, message.To, receiverKeyID
		}
		ownKey, err := m.ownKey(ownKeyID)
		if err != nil {
			return "", err
		}
		peerPublic, err := m.publicKey(ctx, peerMID, peerKeyID, 1)
		if err != nil {
			return "", err
		}
		shared, err = x25519(bytesField(ownKey, 5), peerPublic)
		if err != nil {
			return "", err
		}
	} else {
		group, err := m.groupKeyByID(ctx, message.To, receiverKeyID)
		if err != nil {
			return "", err
		}
		if group.id != receiverKeyID {
			return "", fmt.Errorf("E2EE group key ID does not match")
		}
		var senderPublic []byte
		if message.From == m.session.MID {
			own, err := m.ownKey(senderKeyID)
			if err != nil {
				return "", err
			}
			senderPublic = bytesField(own, 4)
		} else {
			senderPublic, err = m.publicKey(ctx, message.From, senderKeyID, 1)
			if err != nil {
				return "", err
			}
		}
		shared, err = x25519(group.key, senderPublic)
		if err != nil {
			return "", err
		}
		version = group.version
	}
	plaintext, err := decryptPayload(message, chunks, shared, version, senderKeyID, receiverKeyID)
	if err != nil {
		return "", err
	}
	var payload map[string]any
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return "", err
	}
	text, _ := payload["text"].(string)
	return text, nil
}

func (m *Manager) groupKeyByID(ctx context.Context, mid string, groupKeyID int32) (negotiatedKey, error) {
	m.mu.RLock()
	cached, ok := m.group[mid]
	m.mu.RUnlock()
	if ok && cached.id == groupKeyID && time.Now().Before(cached.expires) {
		return cached, nil
	}
	result, err := m.talk.GetE2EEGroupSharedKey(ctx, m.session.AccessToken, mid, groupKeyID)
	if err != nil {
		return negotiatedKey{}, err
	}
	fields, ok := result.(map[int16]any)
	if !ok {
		return negotiatedKey{}, fmt.Errorf("E2EE group key %d result is invalid", groupKeyID)
	}
	value, err := m.unwrapGroupKey(ctx, fields)
	if err != nil {
		fresh, registerErr := m.registerGroupKey(ctx, mid)
		if registerErr != nil {
			return negotiatedKey{}, fmt.Errorf("groupKeyId=%d could not be decrypted: %v; new key registration also failed: %w", groupKeyID, err, registerErr)
		}
		return fresh, nil
	}
	m.mu.Lock()
	m.group[mid] = value
	m.mu.Unlock()
	return value, nil
}

func decryptPayload(message Message, chunks [][]byte, shared []byte, version, senderKeyID, receiverKeyID int32) ([]byte, error) {
	key := sha256.Sum256(join(shared, chunks[0], []byte("Key")))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	if version == 1 {
		iv := foldedSHA256(shared, chunks[0], []byte("IV"))
		if len(chunks[1])%aes.BlockSize != 0 {
			return nil, fmt.Errorf("E2EE CBC ciphertext length is invalid")
		}
		plaintext := make([]byte, len(chunks[1]))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, chunks[1])
		return unpadPKCS7(plaintext)
	}
	if version != 2 {
		return nil, fmt.Errorf("unsupported E2EE message version: %d", version)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := messageAAD(message.To, message.From, senderKeyID, receiverKeyID, version, message.ContentType)
	return gcm.Open(nil, chunks[2], chunks[1], aad)
}

func (m *Manager) keychain() ([]map[int16]any, error) {
	m.mu.RLock()
	if m.keys != nil {
		keys := m.keys
		m.mu.RUnlock()
		return keys, nil
	}
	m.mu.RUnlock()
	if len(m.session.DeviceKeys) > 0 {
		keys := make([]map[int16]any, 0, len(m.session.DeviceKeys))
		for _, device := range m.session.DeviceKeys {
			privateKey, privateErr := base64.StdEncoding.DecodeString(device.PrivateKey)
			publicKey, publicErr := base64.StdEncoding.DecodeString(device.PublicKey)
			if privateErr != nil || publicErr != nil || len(privateKey) != 32 || len(publicKey) != 32 || device.KeyID == 0 {
				return nil, fmt.Errorf("imported E2EE device key is invalid")
			}
			keys = append(keys, map[int16]any{
				2: int64(device.KeyID),
				4: publicKey,
				5: privateKey,
			})
		}
		m.mu.Lock()
		m.keys = keys
		m.mu.Unlock()
		return keys, nil
	}
	metadata, ok := m.session.E2EEMetadata.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("E2EE metadata is missing; QR login is required")
	}
	encrypted, err := base64Field(metadata, "encryptedKeyChain")
	if err != nil {
		return nil, err
	}
	peerPublic, err := base64Field(metadata, "publicKey")
	if err != nil {
		return nil, err
	}
	expectedHash, err := base64Field(metadata, "hashKeyChain")
	if err != nil {
		return nil, err
	}
	privateBytes, err := hex.DecodeString(m.session.QRPrivateKey)
	if err != nil {
		return nil, err
	}
	shared, err := x25519(privateBytes, peerPublic)
	if err != nil {
		return nil, err
	}
	aesKey := sha256.Sum256(join(shared, []byte("Key")))
	block, _ := aes.NewCipher(aesKey[:])
	folded := foldedSHA256(encrypted)
	actualHash := make([]byte, aes.BlockSize)
	block.Encrypt(actualHash, folded)
	if !equal(actualHash, expectedHash) {
		return nil, fmt.Errorf("E2EE keychain integrity check failed")
	}
	plaintext, err := aesCBCDecrypt(shared, encrypted)
	if err != nil {
		return nil, err
	}
	decoded, err := protocol.DecodeStruct(plaintext)
	if err != nil {
		return nil, err
	}
	values, _ := decoded[1].([]any)
	keys := make([]map[int16]any, 0, len(values))
	for _, value := range values {
		if key, ok := value.(map[int16]any); ok {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("E2EE device key was not found")
	}
	m.mu.Lock()
	m.keys = keys
	m.mu.Unlock()
	return keys, nil
}

func (m *Manager) ownKey(keyID int32) (map[int16]any, error) {
	keys, err := m.keychain()
	if err != nil {
		return nil, err
	}
	if keyID == 0 {
		if metadata, ok := m.session.E2EEMetadata.(map[string]any); ok {
			keyID = int32(number(metadata["keyId"]))
		}
	}
	var selected map[int16]any
	for _, key := range keys {
		if int32Field(key, 2) == keyID && keyID != 0 {
			return key, nil
		}
		if selected == nil || int32Field(key, 2) > int32Field(selected, 2) {
			selected = key
		}
	}
	if keyID != 0 {
		available := make([]int32, 0, len(keys))
		for _, key := range keys {
			available = append(available, int32Field(key, 2))
		}
		return nil, fmt.Errorf("E2EE device key was not found keyId=%d available=%v", keyID, available)
	}
	if selected == nil {
		return nil, fmt.Errorf("E2EE device key was not found")
	}
	return selected, nil
}

func (m *Manager) publicKey(ctx context.Context, mid string, keyID, version int32) ([]byte, error) {
	cacheKey := fmt.Sprintf("%s:%d:%d", mid, keyID, version)
	m.mu.RLock()
	cached, ok := m.public[cacheKey]
	m.mu.RUnlock()
	if ok && time.Now().Before(cached.expires) {
		return cached.key, nil
	}
	result, err := m.talk.GetE2EEPublicKey(ctx, m.session.AccessToken, mid, version, keyID)
	if err != nil {
		return nil, err
	}
	fields, ok := result.(map[int16]any)
	if !ok {
		return nil, fmt.Errorf("E2EE public key result is invalid")
	}
	key := bytesField(fields, 4)
	if len(key) != 32 {
		return nil, fmt.Errorf("E2EE public key could not be retrieved")
	}
	m.mu.Lock()
	m.public[cacheKey] = timedKey{expires: time.Now().Add(cacheTTL), key: key}
	m.mu.Unlock()
	return key, nil
}

func (m *Manager) negotiate(ctx context.Context, mid string) (negotiatedKey, error) {
	m.mu.RLock()
	cached, ok := m.direct[mid]
	m.mu.RUnlock()
	if ok && time.Now().Before(cached.expires) {
		return cached, nil
	}
	result, err := m.talk.NegotiateE2EEPublicKey(ctx, m.session.AccessToken, mid)
	if err != nil {
		return negotiatedKey{}, err
	}
	fields, ok := result.(map[int16]any)
	if !ok {
		return negotiatedKey{}, fmt.Errorf("E2EE negotiation result is invalid")
	}
	public, _ := fields[2].(map[int16]any)
	value := negotiatedKey{
		expires: time.Now().Add(negotiationTTL), id: int32Field(public, 2),
		key: bytesField(public, 4), version: int32Field(fields, 3),
	}
	if value.version == 0 {
		value.version = 2
	}
	if value.id == 0 || len(value.key) != 32 {
		return negotiatedKey{}, fmt.Errorf("E2EE key agreement failed")
	}
	m.mu.Lock()
	m.direct[mid] = value
	m.mu.Unlock()
	return value, nil
}

func (m *Manager) groupKey(ctx context.Context, mid string) (negotiatedKey, error) {
	m.mu.RLock()
	cached, ok := m.group[mid]
	m.mu.RUnlock()
	if ok && time.Now().Before(cached.expires) {
		return cached, nil
	}
	result, err := m.talk.GetLastE2EEGroupSharedKey(ctx, m.session.AccessToken, mid)
	if err != nil {
		return negotiatedKey{}, err
	}
	fields, ok := result.(map[int16]any)
	if !ok {
		return negotiatedKey{}, fmt.Errorf("E2EE group key result is invalid")
	}
	if receiver := stringField(fields, 5); receiver != "" && receiver != m.session.MID {
		return m.registerGroupKey(ctx, mid)
	}
	value, err := m.unwrapGroupKey(ctx, fields)
	if err != nil {
		return m.registerGroupKey(ctx, mid)
	}
	m.mu.Lock()
	m.group[mid] = value
	m.mu.Unlock()
	return value, nil
}

func (m *Manager) unwrapGroupKey(ctx context.Context, fields map[int16]any) (negotiatedKey, error) {
	own, err := m.ownKey(int32Field(fields, 6))
	if err != nil {
		return negotiatedKey{}, err
	}
	creatorPublic, err := m.publicKey(ctx, stringField(fields, 3), int32Field(fields, 4), defaultInt32(int32Field(fields, 1), 1))
	if err != nil {
		return negotiatedKey{}, err
	}
	shared, err := x25519(bytesField(own, 5), creatorPublic)
	if err != nil {
		return negotiatedKey{}, err
	}
	privateKey, err := aesCBCDecryptGroupKey(shared, bytesField(fields, 7))
	if err != nil {
		return negotiatedKey{}, err
	}
	value := negotiatedKey{
		expires: time.Now().Add(cacheTTL), id: int32Field(fields, 2), key: privateKey,
		version: defaultInt32(int32Field(fields, 9), 2),
	}
	if value.id == 0 || len(value.key) != 32 {
		return negotiatedKey{}, fmt.Errorf("E2EE group key content is invalid")
	}
	return value, nil
}

func (m *Manager) registerGroupKey(ctx context.Context, mid string) (negotiatedKey, error) {
	result, err := m.talk.GetLastE2EEPublicKeys(ctx, m.session.AccessToken, mid)
	if err != nil {
		return negotiatedKey{}, err
	}
	publicKeys, ok := result.(map[any]any)
	if !ok || len(publicKeys) == 0 {
		return negotiatedKey{}, fmt.Errorf("E2EE group member keys could not be retrieved: %T", result)
	}
	selfFields, _ := publicKeys[m.session.MID].(map[int16]any)
	if selfFields == nil {
		return negotiatedKey{}, fmt.Errorf("this account was not found in E2EE group keys")
	}
	own, err := m.ownKey(int32Field(selfFields, 2))
	if err != nil {
		return negotiatedKey{}, err
	}
	groupPrivate := make([]byte, 32)
	if _, err := rand.Read(groupPrivate); err != nil {
		return negotiatedKey{}, err
	}
	members := make([]string, 0, len(publicKeys))
	keyIDs := make([]int32, 0, len(publicKeys))
	encrypted := make([][]byte, 0, len(publicKeys))
	for rawMID, rawKey := range publicKeys {
		memberMID, midOK := rawMID.(string)
		fields, keyOK := rawKey.(map[int16]any)
		if !midOK || !keyOK || memberMID == "" {
			continue
		}
		keyID, publicKey := int32Field(fields, 2), bytesField(fields, 4)
		if keyID == 0 || len(publicKey) != 32 {
			return negotiatedKey{}, fmt.Errorf("E2EE member public key is invalid: %s", memberMID)
		}
		shared, err := x25519(bytesField(own, 5), publicKey)
		if err != nil {
			return negotiatedKey{}, err
		}
		wrapped, err := aesCBCEncrypt(shared, groupPrivate)
		if err != nil {
			return negotiatedKey{}, err
		}
		members = append(members, memberMID)
		keyIDs = append(keyIDs, keyID)
		encrypted = append(encrypted, wrapped)
	}
	registered, err := m.talk.RegisterE2EEGroupKey(ctx, m.session.AccessToken, mid, members, keyIDs, encrypted)
	if err != nil {
		return negotiatedKey{}, err
	}
	fields, ok := registered.(map[int16]any)
	if !ok {
		return negotiatedKey{}, fmt.Errorf("registerE2EEGroupKey result is invalid: %T", registered)
	}
	value, err := m.unwrapGroupKey(ctx, fields)
	if err != nil {
		return negotiatedKey{}, err
	}
	m.mu.Lock()
	m.group[mid] = value
	m.mu.Unlock()
	return value, nil
}

func aesCBCEncrypt(material, plaintext []byte) ([]byte, error) {
	key := sha256.Sum256(join(material, []byte("Key")))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	padding := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for index := len(plaintext); index < len(padded); index++ {
		padded[index] = byte(padding)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, foldedSHA256(material, []byte("IV"))).CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}

func aesCBCDecrypt(material, ciphertext []byte) ([]byte, error) {
	key := sha256.Sum256(join(material, []byte("Key")))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("AES-CBC ciphertext length is invalid")
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, foldedSHA256(material, []byte("IV"))).CryptBlocks(plaintext, ciphertext)
	return unpadPKCS7(plaintext)
}

func aesCBCDecryptGroupKey(material, ciphertext []byte) ([]byte, error) {
	key := sha256.Sum256(join(material, []byte("Key")))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("AES-CBC group key ciphertext length is invalid")
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, foldedSHA256(material, []byte("IV"))).CryptBlocks(plaintext, ciphertext)
	if unpadded, err := unpadPKCS7(plaintext); err == nil {
		return unpadded, nil
	}
	if len(plaintext) == 32 {
		return plaintext, nil
	}
	return nil, fmt.Errorf("E2EE group key PKCS7 padding is invalid")
}

func unpadPKCS7(value []byte) ([]byte, error) {
	if len(value) == 0 {
		return nil, fmt.Errorf("PKCS7 padding is missing")
	}
	padding := int(value[len(value)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(value) {
		return nil, fmt.Errorf("PKCS7 padding is invalid")
	}
	for _, current := range value[len(value)-padding:] {
		if int(current) != padding {
			return nil, fmt.Errorf("PKCS7 padding is invalid")
		}
	}
	return value[:len(value)-padding], nil
}

func x25519(privateBytes, publicBytes []byte) ([]byte, error) {
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return nil, err
	}
	publicKey, err := ecdh.X25519().NewPublicKey(publicBytes)
	if err != nil {
		return nil, err
	}
	return privateKey.ECDH(publicKey)
}

func foldedSHA256(parts ...[]byte) []byte {
	digest := sha256.Sum256(join(parts...))
	result := make([]byte, 16)
	for index := range result {
		result[index] = digest[index] ^ digest[index+16]
	}
	return result
}

func join(parts ...[]byte) []byte {
	size := 0
	for _, part := range parts {
		size += len(part)
	}
	result := make([]byte, 0, size)
	for _, part := range parts {
		result = append(result, part...)
	}
	return result
}

func messageAAD(to, from string, senderKeyID, receiverKeyID, version, contentType int32) []byte {
	result := append([]byte(to), []byte(from)...)
	for _, value := range []int32{senderKeyID, receiverKeyID, version, contentType} {
		result = append(result, int32Bytes(value)...)
	}
	return result
}

func int32Bytes(value int32) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, uint32(value))
	return result
}

func base64Field(values map[string]any, key string) ([]byte, error) {
	value, _ := values[key].(string)
	if value == "" {
		return nil, fmt.Errorf("E2EE metadata %s is missing", key)
	}
	return base64.StdEncoding.DecodeString(value)
}

func bytesField(fields map[int16]any, id int16) []byte {
	switch value := fields[id].(type) {
	case []byte:
		return value
	case string:
		return []byte(value)
	default:
		return nil
	}
}

func stringField(fields map[int16]any, id int16) string {
	value, _ := fields[id].(string)
	return value
}

func int32Field(fields map[int16]any, id int16) int32 {
	value, _ := fields[id].(int64)
	return int32(value)
}

func number(value any) int64 {
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case int64:
		return typed
	case string:
		parsed, _ := strconv.ParseInt(typed, 10, 64)
		return parsed
	default:
		return 0
	}
}

func defaultInt32(value, fallback int32) int32 {
	if value == 0 {
		return fallback
	}
	return value
}

func chunkBytes(value any) []byte {
	switch typed := value.(type) {
	case []byte:
		return typed
	case string:
		return []byte(typed)
	default:
		return nil
	}
}

func metadataString(metadata map[any]any, key string) string {
	value, _ := metadata[key].(string)
	return value
}

func equal(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}
