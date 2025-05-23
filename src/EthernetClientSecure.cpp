/*
  EthernetClientSecure.cpp - Client Secure class for ESP32
  Copyright (c) 2016 Hristo Gochkov  All right reserved.
  Additions Copyright (C) 2017 Evandro Luis Copercini.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "EthernetClientSecure.h"
#include "esp_crt_bundle.h"
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <errno.h>

#undef inet_aton
#include <Dns.h> 

#undef connect
#undef write
#undef read




EthernetClientSecure::EthernetClientSecure()
{
    _connected = false;
    _timeout = 30000; // Same default as ssl_client

    sslclient = new sslclient_context;
    ssl_init(sslclient);
    sslclient->socket = -1;
    sslclient->handshake_timeout = 120000;
    _use_insecure = false;
    _CA_cert = NULL;
    _cert = NULL;
    _private_key = NULL;
    _pskIdent = NULL;
    _psKey = NULL;
    next = NULL;
    _alpn_protos = NULL;
    _use_ca_bundle = false;
}


EthernetClientSecure::EthernetClientSecure(int sock)
{
    _connected = false;
    _timeout = 30000; // Same default as ssl_client

    sslclient = new sslclient_context;
    ssl_init(sslclient);
    sslclient->socket = sock;
    sslclient->handshake_timeout = 120000;

    if (sock >= 0) {
        _connected = true;
    }

    _CA_cert = NULL;
    _cert = NULL;
    _private_key = NULL;
    _pskIdent = NULL;
    _psKey = NULL;
    next = NULL;
    _alpn_protos = NULL;
}

EthernetClientSecure::~EthernetClientSecure()
{
    stop();
    delete sslclient;
}

EthernetClientSecure &EthernetClientSecure::operator=(const EthernetClientSecure &other)
{
    stop();
    sslclient->socket = other.sslclient->socket;
    _connected = other._connected;
    return *this;
}

void EthernetClientSecure::stop()
{
    if (sslclient->socket >= 0) {
        close(sslclient->socket);
        sslclient->socket = -1;
        _connected = false;
        _peek = -1;
    }
    stop_ssl_socket(sslclient, _CA_cert, _cert, _private_key);
}


int EthernetClientSecure::connect(IPAddress ip, uint16_t port)
{
    if (_pskIdent && _psKey)
        return connect(ip, port, _pskIdent, _psKey);
    return connect(ip, port, _CA_cert, _cert, _private_key);
}

int EthernetClientSecure::connect(IPAddress ip, uint16_t port, int32_t timeout){
    _timeout = timeout;
    return connect(ip, port);
}

int EthernetClientSecure::connect(const char *host, uint16_t port)
{
    if (_pskIdent && _psKey)
        return connect(host, port, _pskIdent, _psKey);
    return connect(host, port, _CA_cert, _cert, _private_key);
}

int EthernetClientSecure::connect(const char *host, uint16_t port, int32_t timeout){
    _timeout = timeout;
    return connect(host, port);
}

int EthernetClientSecure::connect(IPAddress ip, uint16_t port, const char *CA_cert, const char *cert, const char *private_key)
{
    return connect(ip, port, NULL, CA_cert, cert, private_key);
}

int EthernetClientSecure::connect(const char *host, uint16_t port, const char *CA_cert, const char *cert, const char *private_key)
{
    IPAddress address;
    DNSClient dns;
    IPAddress dnsServer = Ethernet.dnsServerIP();
    if (!dnsServer || dnsServer == IPAddress(0, 0, 0, 0)) {
        return 0;
    }
    dns.begin(dnsServer);
    if (!dns.getHostByName(host, address))
        return 0;

    return connect(address, port, host, CA_cert, cert, private_key);
}

int EthernetClientSecure::connect(IPAddress ip, uint16_t port, const char *host, const char *CA_cert, const char *cert, const char *private_key)
{
    int ret = start_ssl_client(sslclient, ip, port, host, _timeout, CA_cert, _use_ca_bundle, cert, private_key, NULL, NULL, _use_insecure, _alpn_protos);
    _lastError = ret;
    if (ret < 0) {
        log_e("start_ssl_client: %d", ret);
        stop();
        return 0;
    }
    _connected = true;
    return 1;
}

int EthernetClientSecure::connect(IPAddress ip, uint16_t port, const char *pskIdent, const char *psKey) {
    return connect(ip.toString().c_str(), port, pskIdent, psKey);
}

int EthernetClientSecure::connect(const char *host, uint16_t port, const char *pskIdent, const char *psKey) {
    log_v("start_ssl_client with PSK");

    IPAddress address;
    DNSClient dns;
    IPAddress dnsServer = Ethernet.dnsServerIP();
    if (!dnsServer || dnsServer == IPAddress(0, 0, 0, 0)) {
        return 0;
    }
    dns.begin(dnsServer);
    if (!dns.getHostByName(host, address))
        return 0;

    int ret = start_ssl_client(sslclient, address, port, host, _timeout, NULL, false, NULL, NULL, pskIdent, psKey, _use_insecure, _alpn_protos);
    _lastError = ret;
    if (ret < 0) {
        log_e("start_ssl_client: %d", ret);
        stop();
        return 0;
    }
    _connected = true;
    return 1;
}

int EthernetClientSecure::peek(){
    if(_peek >= 0){
        return _peek;
    }
    _peek = timedRead();
    return _peek;
}

size_t EthernetClientSecure::write(uint8_t data)
{
    return write(&data, 1);
}

int EthernetClientSecure::read()
{
    uint8_t data = -1;
    int res = read(&data, 1);
    if (res < 0) {
        return res;
    }
    return data;
}

size_t EthernetClientSecure::write(const uint8_t *buf, size_t size)
{
    if (!_connected) {
        return 0;
    }
    int res = send_ssl_data(sslclient, buf, size);
    if (res < 0) {
        stop();
        res = 0;
    }
    return res;
}

int EthernetClientSecure::read(uint8_t *buf, size_t size)
{
    int peeked = 0;
    int avail = available();
    if ((!buf && size) || avail <= 0) {
        return -1;
    }
    if(!size){
        return 0;
    }
    if(_peek >= 0){
        buf[0] = _peek;
        _peek = -1;
        size--;
        avail--;
        if(!size || !avail){
            return 1;
        }
        buf++;
        peeked = 1;
    }
    
    int res = get_ssl_receive(sslclient, buf, size);
    if (res < 0) {
        stop();
        return peeked?peeked:res;
    }
    return res + peeked;
}

int EthernetClientSecure::available()
{
    int peeked = (_peek >= 0);
    if (!_connected) {
        return peeked;
    }
    int res = data_to_read(sslclient);
    if (res < 0) {
        stop();
        return peeked?peeked:res;
    }
    return res+peeked;
}

uint8_t EthernetClientSecure::connected()
{
    uint8_t dummy = 0;
    read(&dummy, 0);

    return _connected;
}

void EthernetClientSecure::setInsecure()
{
    _CA_cert = NULL;
    _cert = NULL;
    _private_key = NULL;
    _pskIdent = NULL;
    _psKey = NULL;
    _use_insecure = true;
}

void EthernetClientSecure::setCACert (const char *rootCA)
{
    _CA_cert = rootCA;
}

 void EthernetClientSecure::setCACertBundle(const uint8_t * bundle)
 {
    if (bundle != NULL)
    {
        arduino_esp_crt_bundle_set(bundle);
        _use_ca_bundle = true;
    } else {
        arduino_esp_crt_bundle_detach(NULL);
        _use_ca_bundle = false;
    }
 }

void EthernetClientSecure::setCertificate (const char *client_ca)
{
    _cert = client_ca;
}

void EthernetClientSecure::setPrivateKey (const char *private_key)
{
    _private_key = private_key;
}

void EthernetClientSecure::setPreSharedKey(const char *pskIdent, const char *psKey) {
    _pskIdent = pskIdent;
    _psKey = psKey;
}

bool EthernetClientSecure::verify(const char* fp, const char* domain_name)
{
    if (!sslclient)
        return false;

    return verify_ssl_fingerprint(sslclient, fp, domain_name);
}

char *EthernetClientSecure::_streamLoad(Stream& stream, size_t size) {
  char *dest = (char*)malloc(size+1);
  if (!dest) {
    return nullptr;
  }
  if (size != stream.readBytes(dest, size)) {
    free(dest);
    dest = nullptr;
    return nullptr;
  }
  dest[size] = '\0';
  return dest;
}

bool EthernetClientSecure::loadCACert(Stream& stream, size_t size) {
  if (_CA_cert != NULL) free(const_cast<char*>(_CA_cert));
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setCACert(dest);
    ret = true;
  }
  return ret;
}

bool EthernetClientSecure::loadCertificate(Stream& stream, size_t size) {
  if (_cert != NULL) free(const_cast<char*>(_cert));
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setCertificate(dest);
    ret = true;
  }
  return ret;
}

bool EthernetClientSecure::loadPrivateKey(Stream& stream, size_t size) {
  if (_private_key != NULL) free(const_cast<char*>(_private_key));
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setPrivateKey(dest);
    ret = true;
  }
  return ret;
}

int EthernetClientSecure::lastError(char *buf, const size_t size)
{
    if (!_lastError) {
        return 0;
    }
    mbedtls_strerror(_lastError, buf, size);
    return _lastError;
}

void EthernetClientSecure::setHandshakeTimeout(unsigned long handshake_timeout)
{
    sslclient->handshake_timeout = handshake_timeout * 1000;
}

void EthernetClientSecure::setAlpnProtocols(const char **alpn_protos)
{
    _alpn_protos = alpn_protos;
}
int EthernetClientSecure::setTimeout(uint32_t seconds)
{
   
    _timeout = seconds * 1000;
    if (sslclient->socket >= 0) {
        struct timeval tv;
        tv.tv_sec = seconds;
        tv.tv_usec = 0;
        /*
        if(setSocketOption(SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) < 0) {
            return -1;
        }
        return setSocketOption(SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval));
        */
        return -1;
    }
    else {
        return 0;
    }
}
int EthernetClientSecure::fd() const
{
    return sslclient->socket;
}

