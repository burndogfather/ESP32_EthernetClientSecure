// EthernetClientSecure.cpp - Implementation for Ethernet-compatible secure client using mbedTLS

#include "EthernetClientSecure.h"

EthernetClientSecure::EthernetClientSecure() {
  sslclient = new sslclient_context;
  memset(sslclient, 0, sizeof(sslclient_context));
  _timeout = 30000;
  _use_insecure = false;
  _CA_cert = nullptr;
  _cert = nullptr;
  _private_key = nullptr;
  _pskIdent = nullptr;
  _psKey = nullptr;
  _use_ca_bundle = false;
  _alpn_protos = nullptr;
}

EthernetClientSecure::EthernetClientSecure(int socket) : EthernetClientSecure() {
  sslclient->socket = socket;
}

EthernetClientSecure::~EthernetClientSecure() {
  stop();
  delete sslclient;
}

int EthernetClientSecure::connect(IPAddress ip, uint16_t port) {
  char ipStr[16];
  snprintf(ipStr, sizeof(ipStr), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  return connect(ipStr, port);
}

int EthernetClientSecure::connect(const char *host, uint16_t port) {
  return connect(host, port, _timeout);
}

int EthernetClientSecure::connect(const char *host, uint16_t port, int32_t timeout) {
  if (!_ethClient.connect(host, port)) {
	return 0;
  }
  sslclient->socket = _ethClient.fd();
  return start_ssl_client(sslclient, host, _CA_cert, _cert, _private_key, _pskIdent, _psKey, _use_insecure, _alpn_protos);
}

int EthernetClientSecure::connect(IPAddress ip, uint16_t port, int32_t timeout) {
  char ipStr[16];
  snprintf(ipStr, sizeof(ipStr), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  return connect(ipStr, port, timeout);
}

int EthernetClientSecure::connect(IPAddress ip, uint16_t port, const char *rootCABuff, const char *cli_cert, const char *cli_key) {
  setCACert(rootCABuff);
  setCertificate(cli_cert);
  setPrivateKey(cli_key);
  return connect(ip, port);
}

int EthernetClientSecure::connect(const char *host, uint16_t port, const char *rootCABuff, const char *cli_cert, const char *cli_key) {
  setCACert(rootCABuff);
  setCertificate(cli_cert);
  setPrivateKey(cli_key);
  return connect(host, port);
}

int EthernetClientSecure::peek() {
  if (_peek >= 0) return _peek;
  _peek = read();
  return _peek;
}

size_t EthernetClientSecure::write(uint8_t data) {
  return write(&data, 1);
}

size_t EthernetClientSecure::write(const uint8_t *buf, size_t size) {
  return send_ssl_data(sslclient, buf, size);
}

int EthernetClientSecure::read() {
  uint8_t c;
  if (_peek >= 0) {
	c = _peek;
	_peek = -1;
	return c;
  }
  if (read(&c, 1) < 0) return -1;
  return c;
}

int EthernetClientSecure::read(uint8_t *buf, size_t size) {
  return get_ssl_receive(sslclient, buf, size);
}

int EthernetClientSecure::available() {
  return data_to_read(sslclient);
}

void EthernetClientSecure::stop() {
  stop_ssl_socket(sslclient, _CA_cert, _cert, _private_key);
  _ethClient.stop();
}

uint8_t EthernetClientSecure::connected() {
  return _ethClient.connected();
}

void EthernetClientSecure::setInsecure() {
  _use_insecure = true;
}

void EthernetClientSecure::setCACert(const char *rootCA) {
  _CA_cert = rootCA;
}

void EthernetClientSecure::setCertificate(const char *client_ca) {
  _cert = client_ca;
}

void EthernetClientSecure::setPrivateKey(const char *private_key) {
  _private_key = private_key;
}

void EthernetClientSecure::setPreSharedKey(const char *pskIdent, const char *psKey) {
  _pskIdent = pskIdent;
  _psKey = psKey;
}

void EthernetClientSecure::setAlpnProtocols(const char **alpn_protos) {
  _alpn_protos = alpn_protos;
}

int EthernetClientSecure::setTimeout(uint32_t seconds) {
  _timeout = seconds * 1000;
  return _timeout;
}

int EthernetClientSecure::lastError(char *buf, const size_t size) {
  strncpy(buf, _lastError, size);
  return _lastError[0] ? -1 : 0;
}

EthernetClientSecure &EthernetClientSecure::operator=(const EthernetClientSecure &other) {
  if (this != &other) {
	sslclient = other.sslclient;
	_ethClient = other._ethClient;
  }
  return *this;
}

bool EthernetClientSecure::operator==(const EthernetClientSecure &other) {
  return _ethClient == other._ethClient;
}

char *EthernetClientSecure::_streamLoad(Stream &stream, size_t size) {
  char *dest = (char *)malloc(size + 1);
  if (!dest) return nullptr;
  stream.readBytes(dest, size);
  dest[size] = '\0';
  return dest;
}

bool EthernetClientSecure::loadCACert(Stream &stream, size_t size) {
  char *buff = _streamLoad(stream, size);
  if (!buff) return false;
  setCACert(buff);
  return true;
}

bool EthernetClientSecure::loadCertificate(Stream &stream, size_t size) {
  char *buff = _streamLoad(stream, size);
  if (!buff) return false;
  setCertificate(buff);
  return true;
}

bool EthernetClientSecure::loadPrivateKey(Stream &stream, size_t size) {
  char *buff = _streamLoad(stream, size);
  if (!buff) return false;
  setPrivateKey(buff);
  return true;
}

bool EthernetClientSecure::verify(const char *fingerprint, const char *domain_name) {
  return verify_ssl_fingerprint(sslclient, fingerprint, domain_name);
}
