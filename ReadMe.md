# *Crypto API*

This is a simple Spring Boot API for hashing, encrypting, and decrypting secrets using BCrypt and RSA encryption.

## Endpoints & Usage

### 1. Hash a Secret

**Endpoint:** `POST /crypto/hash`

**Description:** Hashes a given secret using BCrypt.

**Request:**

```bash
curl -X POST "http://localhost:8080/crypto/hash" -d "secret=mySecret" -H "Content-Type: application/x-www-form-urlencoded"
```

**Response:**

```json
"$2a$10$e0NRVtEw7BqLgBdC5I.wFe7LRNsc1.dE30yGMQX7bVtU1Rqrrl/Wm"
```

---

### 2. Encrypt a Hashed Secret (Query Parameter)

**Endpoint:** `POST /crypto/encrypt`

**Description:** Encrypts a hashed secret using RSA encryption.

**Request:**

```bash
curl -X POST "http://localhost:8080/crypto/encrypt" -d "hashedSecret=$2a$10$e0NRVtEw7BqLgBdC5I.wFe7LRNsc1.dE30yGMQX7bVtU1Rqrrl/Wm" -H "Content-Type: application/x-www-form-urlencoded"
```

**Response:**

```json
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtz..."
```

**Note:** Due to special characters in BCrypt hashes, passing them as query parameters may cause data loss.

---

### 3. Encrypt a Hashed Secret (JSON Body)

**Endpoint:** `POST /crypto/encryptJsonBody`

**Description:** Encrypts a hashed secret using RSA encryption, passed in JSON format.

**Request:**

```bash
curl -X POST "http://localhost:8080/crypto/encryptJsonBody" -H "Content-Type: application/json" -d '{"hashedSecret": "$2a$10$e0NRVtEw7BqLgBdC5I.wFe7LRNsc1.dE30yGMQX7bVtU1Rqrrl/Wm"}'
```

**Response:**

```json
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtz..."
```

---

### 4. Decrypt Encrypted Data

**Endpoint:** `POST /crypto/decrypt`

**Description:** Decrypts an encrypted hashed secret using RSA private key.

**Request:**

```bash
curl -X POST "http://localhost:8080/crypto/decrypt" -d "encryptedData=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtz..." -H "Content-Type: application/x-www-form-urlencoded"
```

**Response:**

```json
"$2a$10$e0NRVtEw7BqLgBdC5I.wFe7LRNsc1.dE30yGMQX7bVtU1Rqrrl/Wm"
```

---

### 5. Welcome Message

**Endpoint:** `GET /crypto/welcome`

**Description:** Returns a simple welcome message.

**Request:**

```bash
curl -X GET "http://localhost:8080/crypto/welcome"
```

**Response:**

```json
"Welcome to Spring Boot!"
```

## Notes

- The API assumes it is running locally on port 8080. Update the URL accordingly if running on a different host or port.
- The RSA encryption and decryption depend on `CryptoService`, which manages key pairs.
- Using JSON (`encryptJsonBody`) is preferred over query parameters (`encrypt`) for handling hashed secrets safely.

## Running the Application

To run the Spring Boot application, use:

```bash
mvn spring-boot:run
```

OR

```bash
java -jar target/your-app.jar
```

Ensure that dependencies are installed and configured properly.

---

### Author

**Damianos Pappas**

