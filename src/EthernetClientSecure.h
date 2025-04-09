/*
  EthernetClientSecure.h - Ethernet-compatible secure client for ESP32 using mbedTLS
  Adapted from WiFiClientSecure by burndogfather for use with Ethernet.h
*/

#ifndef EthernetClientSecure_h
#define EthernetClientSecure_h

#include "Arduino.h"
#include "IPAddress.h"
#include <Client.h>
#include <Ethernet.h>

extern "C" {
  #include "ssl_client.h"
}

class EthernetClientSecure : public Client
{
protected:
	sslclient_context *sslclient;

	int _lastError = 0;
	int _peek = -1;
	int _timeout;
	bool _use_insecure;
	const char *_CA_cert;
	const char *_cert;
	const char *_private_key;
	const char *_pskIdent; // identity for PSK cipher suites
	const char *_psKey;    // key in hex for PSK cipher suites
	const char **_alpn_protos;
	bool _use_ca_bundle;
	EthernetClient _ethClient;

public:
	EthernetClientSecure *next;

	EthernetClientSecure();
	EthernetClientSecure(int socket);
	~EthernetClientSecure();

	int connect(IPAddress ip, uint16_t port);
	int connect(IPAddress ip, uint16_t port, int32_t timeout);
	int connect(const char *host, uint16_t port);
	int connect(const char *host, uint16_t port, int32_t timeout);
	int connect(IPAddress ip, uint16_t port, const char *rootCABuff, const char *cli_cert, const char *cli_key);
	int connect(const char *host, uint16_t port, const char *rootCABuff, const char *cli_cert, const char *cli_key);
	int connect(IPAddress ip, uint16_t port, const char *pskIdent, const char *psKey);
	int connect(const char *host, uint16_t port, const char *pskIdent, const char *psKey);
	int connect(IPAddress ip, uint16_t port, const char *host, const char *CA_cert, const char *cert, const char *private_key);

	int peek();
	size_t write(uint8_t data);
	size_t write(const uint8_t *buf, size_t size);
	int available();
	int read();
	int read(uint8_t *buf, size_t size);
	void flush() {}
	void stop();
	uint8_t connected();

	int lastError(char *buf, const size_t size);
	void setInsecure();
	void setPreSharedKey(const char *pskIdent, const char *psKey);
	void setCACert(const char *rootCA);
	void setCertificate(const char *client_ca);
	void setPrivateKey(const char *private_key);
	bool loadCACert(Stream &stream, size_t size);
	void setCACertBundle(const uint8_t *bundle);
	bool loadCertificate(Stream &stream, size_t size);
	bool loadPrivateKey(Stream &stream, size_t size);
	bool verify(const char *fingerprint, const char *domain_name);
	void setHandshakeTimeout(unsigned long handshake_timeout);
	void setAlpnProtocols(const char **alpn_protos);
	const mbedtls_x509_crt *getPeerCertificate() { return mbedtls_ssl_get_peer_cert(&sslclient->ssl_ctx); };
	bool getFingerprintSHA256(uint8_t sha256_result[32]) { return get_peer_fingerprint(sslclient, sha256_result); };
	int setTimeout(uint32_t seconds);
	int fd() const;

	operator bool() {
		return connected();
	}

	EthernetClientSecure &operator=(const EthernetClientSecure &other);
	bool operator==(const bool value) {
		return bool() == value;
	}
	bool operator!=(const bool value) {
		return bool() != value;
	}
	bool operator==(const EthernetClientSecure &);
	bool operator!=(const EthernetClientSecure &rhs) {
		return !this->operator==(rhs);
	};

	int socket() {
		return sslclient->socket = -1;
	}

private:
	char *_streamLoad(Stream &stream, size_t size);

	using Print::write;
};

#endif /* EthernetClientSecure_h */
