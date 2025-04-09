EthernetClientSecure
================

WiFiClientSecure 클래스는 TLS(SSL)를 사용한 보안 연결을 지원하며, 
WiFiClient 클래스를 상속받아 해당 클래스의 모든 인터페이스를 포함합니다. 
WiFiClientSecure 클래스를 사용하여 보안 연결을 설정하는 세 가지 방법 : 
- 루트 인증서(CA 인증서) 사용 
- 루트 CA 인증서 + 클라이언트 인증서 및 키 조합 사용 
- 미리 공유된 키(PSK, Pre-Shared Key) 사용 

https://github.com/tuan-karma/ESP32_WiFiClientSecure 의 Ethernet 포팅버전입니다. 