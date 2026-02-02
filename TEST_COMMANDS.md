# hyper-nat P0/P1 테스트 명령어

## 환경 설정 (사전 준비)

```powershell
# 관리자 권한 PowerShell에서 OpenClaw Gateway 실행
# (작업 스케줄러에서 "가장 높은 수준의 권한으로 실행" 설정)
```

---

## 테스트 명령어

### 1. hyper-nat 시작

```powershell
cd C:\WorkSpace\projects\hyper-nat
.\hyper-nat.exe -config configs\hyper-nat.yaml -verbose
```

### 2. 상태 확인 (P1 - status 명령)

```powershell
.\hyper-nat.exe status
```

### 3. VM에서 인터넷 테스트 (NAT 적용)

```bash
# SSH 접속
ssh root@172.17.240.21

# ICMP 테스트
ping -c 2 8.8.8.8

# TCP 테스트
curl -s https://httpbin.org/ip

# UDP 테스트 (DNS)
echo -e '\x00' | nc -u -w2 8.8.8.8 53
```

### 4. VM에서 호스트 네트워크 테스트 (bypass)

```bash
# ICMP 테스트
ping -c 2 192.168.45.233

# TCP 테스트
curl -s http://192.168.45.233:8080
```

### 5. 설정 핫 리로드 테스트 (P1)

```powershell
# configs\hyper-nat.yaml 수정 후 5초 대기
# hyper-nat 로그에서 "Configuration reloaded" 확인
```

### 6. TCP 타임아웃 테스트 (P0 - 단축 테스트)

```powershell
# nat/engine.go에서 tcpEstablishedTimeout을 30초로 변경
# go build -o hyper-nat.exe ./cmd/hyper-nat
# 연결 생성 후 30초 대기 → status에서 연결 제거 확인
```

### 7. 정리

```powershell
taskkill /F /IM hyper-nat.exe
```

---

## 테스트 결과 요약 (2026-02-02)

| 기능 | 테스트 항목 | 결과 |
|------|-------------|------|
| P0-1 | 에러 복구 로직 | ✅ 지수 백오프 재시도 구현 완료 |
| P0-2 | TCP 타임아웃 | ✅ half-open 60초, ESTABLISHED 2시간 타임아웃 구현 |
| P1-3 | status 명령 | ✅ SNAT/DNAT 정보 모두 표시 |
| P1-4 | 핫 리로드 | ✅ "[INFO] [CONFIG] Configuration reloaded successfully" 로그 출력 |
| P1-5 | DNAT (Port Forwarding) | ✅ Phase 1 구현 완료, status에서 표시 |
| 기본 | 인터넷 NAT | ✅ 정상 작동 (NATted 카운트 증가) |
| 기본 | 호스트 네트워크 bypass | ✅ 정상 작동 (Bypassed 카운트 증가) |
