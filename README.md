# Hyper-NAT

Windows용 선택적 NAT 소프트웨어입니다. WinDivert를 사용하여 패킷을 가로채고, 목적지에 따라 NAT를 적용하거나 우회(bypass)합니다.

## 문제 상황

Windows의 NetNat(`New-NetNat`)는 모든 아웃바운드 트래픽에 무조건 SNAT를 적용합니다. 특정 목적지만 NAT를 제외하는 기능이 없습니다.

**예시 시나리오:**
- Hyper-V VM들이 `172.17.240.0/24` 대역 사용
- 호스트 네트워크 `192.168.45.0/24`로 가는 트래픽은 원본 IP 유지 필요
- 인터넷으로 가는 트래픽만 NAT 적용

## 해결 방법

Hyper-NAT는 WinDivert로 패킷을 가로채서:
- **bypass**: 특정 목적지 → NAT 제외, 소스 IP 유지
- **nat**: 나머지 목적지 → NAT 적용, 소스 IP 변환

---

## 빌드

### 요구사항

- Windows 10/11 또는 Windows Server 2016+
- Go 1.21+
- 관리자 권한 (실행 시)

### 빌드 방법

```powershell
# 프로젝트 디렉토리로 이동
cd hyper-nat

# 의존성 다운로드
go mod tidy

# 빌드
go build -o hyper-nat.exe ./cmd/hyper-nat

# 또는 빌드 스크립트 사용
.\scripts\build.ps1
```

### WinDivert 설치

WinDivert 파일을 실행 파일과 같은 디렉토리에 배치해야 합니다:

1. [WinDivert 다운로드](https://reqrypt.org/windivert.html) (v2.2 권장)
2. 압축 해제 후 다음 파일을 `hyper-nat.exe`와 같은 디렉토리에 복사:
   - `WinDivert.dll`
   - `WinDivert64.sys`

```
hyper-nat/
├── hyper-nat.exe
├── WinDivert.dll      ← 필수
├── WinDivert64.sys    ← 필수
└── configs/
    └── hyper-nat.yaml
```

---

## 설정

### 설정 파일 구조

`configs/hyper-nat.yaml` 파일을 편집합니다:

```yaml
# NAT에 사용할 외부 IP (호스트의 외부 네트워크 IP)
nat_ip: 192.168.45.57

# 내부 네트워크 대역 (VM들이 사용하는 대역, CIDR 표기)
internal_network: 172.17.240.0/24

# 호스트의 내부 인터페이스 IP (NAT 대상에서 제외, 선택사항)
host_internal_ip: 172.17.240.1

# 규칙 (위에서부터 순서대로 매칭, 첫 매칭 적용)
rules:
  # 내부 네트워크로 가는 트래픽은 NAT 제외 (VM <-> VM 통신)
  - name: "내부 네트워크"
    destination: 172.17.240.0/24
    action: bypass

  # 호스트 네트워크로 가는 트래픽은 NAT 제외 (소스 IP 유지)
  - name: "호스트 네트워크"
    destination: 192.168.45.0/24
    action: bypass

  # 그 외 모든 트래픽은 NAT 적용
  - name: "인터넷"
    destination: 0.0.0.0/0
    action: nat
```

### 설정 항목 설명

| 항목 | 필수 | 설명 |
|------|------|------|
| `nat_ip` | O | NAT 변환에 사용할 호스트 IP. 외부에서 접근 가능한 IP |
| `internal_network` | O | NAT를 적용할 내부 네트워크 대역 (CIDR) |
| `host_internal_ip` | X | 호스트의 내부 인터페이스 IP. 설정 시 해당 IP에서 나가는 트래픽은 NAT 제외 |
| `rules` | O | 목적지별 NAT 규칙 목록 |

### 규칙 작성 방법

규칙은 **위에서 아래로 순차적으로** 매칭됩니다. 먼저 매칭된 규칙이 적용됩니다.

```yaml
rules:
  # 1. 가장 구체적인 규칙을 먼저
  - name: "특정 서버"
    destination: 10.0.0.5/32    # 단일 IP
    action: bypass

  # 2. 서브넷 규칙
  - name: "사내 네트워크"
    destination: 10.0.0.0/8     # 전체 대역
    action: bypass

  # 3. 마지막에 기본 규칙 (catch-all)
  - name: "기타"
    destination: 0.0.0.0/0      # 모든 IP
    action: nat
```

**action 옵션:**
- `bypass`: NAT 적용 안함 (소스 IP 유지)
- `nat`: NAT 적용 (소스 IP를 `nat_ip`로 변환)

---

## 실행

### 기본 실행

**관리자 권한 PowerShell에서 실행:**

```powershell
# 관리자로 PowerShell 열기 (Win+X → Windows Terminal (Admin))

cd C:\path\to\hyper-nat
.\hyper-nat.exe -config configs\hyper-nat.yaml
```

### 명령줄 옵션

```
옵션:
  -config string   설정 파일 경로 (기본값: "hyper-nat.yaml")
  -verbose         상세 로깅 활성화 (디버그용)
  -version         버전 정보 출력
```

### 실행 예시

```powershell
# 기본 실행
.\hyper-nat.exe -config configs\hyper-nat.yaml

# 상세 로그 출력 (디버깅 시)
.\hyper-nat.exe -config configs\hyper-nat.yaml -verbose

# 버전 확인
.\hyper-nat.exe -version
```

### 종료

`Ctrl+C`를 누르면 정상 종료됩니다. 종료 시 통계가 출력됩니다:

```
[INFO] [MAIN] Received signal interrupt, shutting down...
[INFO] [ENGINE] Stopped
[INFO] [MAIN] Final statistics:
[INFO] [MAIN]   Packets processed: 1234
[INFO] [MAIN]   Packets NATted: 1000
[INFO] [MAIN]   Packets bypassed: 200
[INFO] [MAIN]   Packets dropped: 34
[INFO] [MAIN]   Active connections: 5
[INFO] [MAIN]   Total connections: 150
[INFO] [MAIN] Hyper-NAT stopped
```

---

## 로그 읽는 방법

### 로그 형식

```
[시간] [레벨] [컴포넌트] 메시지
```

### 로그 레벨

| 레벨 | 설명 |
|------|------|
| `INFO` | 일반 정보 (시작, 종료, 새 연결 등) |
| `DEBUG` | 상세 정보 (`-verbose` 옵션 시 출력) |
| `WARN` | 경고 |
| `ERROR` | 오류 |

### 로그 예시 및 해석

**시작 로그:**
```
[INFO] [MAIN] Hyper-NAT v0.1.0 starting...
[INFO] [MAIN] Configuration loaded from configs/hyper-nat.yaml
[INFO] [MAIN] NAT IP: 192.168.45.57
[INFO] [MAIN] Internal Network: 172.17.240.0/24
[INFO] [MAIN] Rules:
[INFO] [MAIN]   1. 내부 네트워크: 172.17.240.0/24 -> bypass
[INFO] [MAIN]   2. 호스트 네트워크: 192.168.45.0/24 -> bypass
[INFO] [MAIN]   3. 인터넷: 0.0.0.0/0 -> nat
```

**새 NAT 연결:**
```
[INFO] [NAT] New TCP 172.17.240.21:54321 → 142.250.207.46:443 (mapped to :40001)
```
- VM `172.17.240.21`의 포트 `54321`에서
- 외부 `142.250.207.46:443` (Google)으로 연결
- NAT 포트 `40001`로 매핑됨

**TCP 상태 변경 (verbose 모드):**
```
[DEBUG] [TABLE] TCP state: NEW → SYN_SENT
[DEBUG] [TABLE] TCP state: SYN_SENT → SYN_RECEIVED
[DEBUG] [TABLE] TCP state: SYN_RECEIVED → ESTABLISHED
```

**ICMP NAT (ping):**
```
[INFO] [NAT] New ICMP 172.17.240.21 → 8.8.8.8 (ID:44 mapped to ID:40006)
[DEBUG] [NAT] Outbound ICMP 172.17.240.21 → 8.8.8.8 (ID:44 → NAT ID:40006)
[DEBUG] [NAT] Reverse ICMP 8.8.8.8 → 172.17.240.21 (NAT ID:40006 → ID:44)
```
- ICMP Echo Request (ping)가 NAT 처리됨
- ICMP Identifier가 NAT ID로 변환되어 추적

**Bypass 트래픽 (verbose 모드):**
```
[DEBUG] [BYPASS] TCP 172.17.240.21:54322 → 192.168.45.100:22 (rule: 호스트 네트워크)
```
- 규칙 "호스트 네트워크"에 의해 NAT 없이 통과

**연결 정리:**
```
[INFO] [TABLE] Cleaned 5 expired entries, 10 remaining
```
- 타임아웃된 연결 5개 정리, 활성 연결 10개

**에러:**
```
[ERROR] [ENGINE] Outbound recv error: The I/O operation has been aborted...
```
- 종료 시 정상적으로 발생하는 메시지 (무시 가능)

---

## 동작 원리

### 아키텍처: 듀얼 레이어 캡처

```
┌─────────────────────────────────────────────────────────────────┐
│                        WinDivert                                │
├─────────────────────────────────────────────────────────────────┤
│  Outbound Handle                │  Inbound Handle               │
│  (LayerNetworkForward)          │  (LayerNetwork)               │
│                                 │                               │
│  VM → 인터넷 트래픽 캡처         │  인터넷 → NAT IP 응답 캡처     │
├─────────────────────────────────┴───────────────────────────────┤
│                                                                 │
│  VM (172.17.240.21)  ──SNAT──▶  NAT IP (192.168.45.57)         │
│                      ◀──DNAT──                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 아웃바운드 (VM → 인터넷)

1. VM에서 패킷 발신
2. WinDivert가 `LayerNetworkForward`에서 패킷 캡처
3. 소스 IP가 `internal_network`인지 확인
4. 목적지 IP로 규칙 매칭
5. **bypass**: 패킷 그대로 전달
6. **nat**: 소스 IP/포트 변환 → 연결 추적 테이블에 기록 → 전달

### 인바운드 (인터넷 → VM, 응답)

1. 외부에서 NAT IP로 패킷 수신
2. WinDivert가 `LayerNetwork`에서 패킷 캡처
3. 연결 추적 테이블에서 역방향 조회
4. 목적지 IP/포트를 원래 VM IP/포트로 복원
5. VM으로 전달

---

## 테스트

### VM에서 인터넷 연결 테스트

```bash
# VM에 SSH 접속 후
ssh root@172.17.240.21

# HTTPS 테스트 (TCP)
curl -s -o /dev/null -w "%{http_code}\n" https://www.google.com
# 출력: 200

# 외부 IP 확인 (NAT IP의 공인 IP가 표시되어야 함)
curl ifconfig.me

# DNS 테스트 (UDP)
nslookup google.com
```

### Bypass 테스트

```bash
# VM에서 호스트 네트워크로 접속 시 소스 IP 유지 확인
# 호스트 네트워크의 서버에서 연결 로그 확인
ssh user@192.168.45.100
# → 소스 IP가 172.17.240.21로 표시되어야 함 (NAT 안됨)
```

### 유닛 테스트

```powershell
go test ./config/... ./nat/...
```

---

## 제한사항

- IPv4만 지원
- TCP/UDP/ICMP 지원 (ICMP는 Echo Request/Reply만)
- 단일 NAT IP만 지원
- NAT 포트/ID 범위: 40000-60000 (20,000개)

---

## 트러블슈팅

### WinDivert.Open() 실패

```
failed to open outbound WinDivert handle: failed to load WinDivert.dll
```

**해결:**
1. 관리자 권한으로 실행했는지 확인
2. `WinDivert.dll`, `WinDivert64.sys` 파일이 `hyper-nat.exe`와 같은 디렉토리에 있는지 확인
3. Windows Defender나 안티바이러스가 차단하는지 확인

### 패킷이 드롭됨 / 연결 안됨

**확인 사항:**
1. `nat_ip`가 호스트의 실제 외부 IP인지 확인
2. `internal_network`가 VM 네트워크 대역과 일치하는지 확인
3. `-verbose` 옵션으로 실행하여 패킷 흐름 확인

### Windows 방화벽 문제

Hyper-V 내부 스위치를 통한 패킷 포워딩이 차단될 수 있습니다:

```powershell
# 방화벽 규칙 추가 (관리자 권한)
New-NetFirewallRule -DisplayName "Hyper-NAT Inbound" -Direction Inbound -Action Allow -Protocol Any -LocalAddress 172.17.240.0/24
New-NetFirewallRule -DisplayName "Hyper-NAT Outbound" -Direction Outbound -Action Allow -Protocol Any -RemoteAddress 172.17.240.0/24
```

### 연결 추적 테이블 오버플로우

```
no available NAT ports
```

**해결:**
- 동시 연결이 20,000개를 초과하면 발생
- TCP/UDP 타임아웃 대기 후 자동 정리됨
- 장시간 운영 시 연결이 계속 쌓이면 프로그램 재시작

---

## 프로젝트 구조

```
hyper-nat/
├── cmd/
│   ├── hyper-nat/main.go     # CLI 진입점
│   └── test-capture/main.go  # 패킷 캡처 테스트 도구
├── config/                   # 설정 파싱
│   ├── config.go
│   └── config_test.go
├── configs/
│   └── hyper-nat.yaml        # 설정 파일
├── nat/                      # NAT 엔진
│   ├── engine.go             # 메인 처리 루프 (트리플 레이어)
│   ├── rules.go              # 규칙 매칭
│   ├── table.go              # 연결 추적 테이블
│   └── table_test.go
├── packet/                   # 패킷 처리
│   ├── modifier.go           # NAT 적용 (IP/포트/ICMP ID)
│   └── parser.go             # IPv4/TCP/UDP/ICMP 파싱
├── scripts/
│   └── build.ps1             # 빌드 스크립트
└── windivert/                # WinDivert Go 래퍼
    ├── windivert.go
    └── windivert_windows.go
```

---

## 라이선스

MIT License

## 참조

- [WinDivert 공식 문서](https://reqrypt.org/windivert-doc.html)
- [WinDivert 필터 문법](https://reqrypt.org/windivert-doc.html#filter_language)
- [WinDivert 다운로드](https://reqrypt.org/windivert.html)
