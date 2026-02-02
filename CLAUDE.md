# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 빌드 및 실행

```powershell
# 빌드
go build -o hyper-nat.exe ./cmd/hyper-nat

# 테스트
go test ./...

# 단일 패키지 테스트
go test ./nat/...
go test ./config/...

# 포그라운드 실행 (관리자 권한 필수)
.\hyper-nat.exe -config configs\hyper-nat.yaml -verbose

# 로그 파일과 함께 실행
.\hyper-nat.exe -config configs\hyper-nat.yaml -logfile logs\hyper-nat.log -verbose
```

**필수 파일:** WinDivert.dll, WinDivert64.sys를 hyper-nat.exe와 같은 디렉토리에 배치

### Windows 서비스 모드

```powershell
# 서비스 설치 (관리자 권한 필수)
.\hyper-nat.exe install -config C:\hyper-nat\configs\hyper-nat.yaml -logfile C:\hyper-nat\logs\hyper-nat.log

# 서비스 시작
.\hyper-nat.exe start
# 또는: net start HyperNAT

# 서비스 상태 확인
.\hyper-nat.exe status

# 서비스 중지
.\hyper-nat.exe stop
# 또는: net stop HyperNAT

# 서비스 제거
.\hyper-nat.exe uninstall
```

**서비스 특징:**
- PC 부팅 시 자동 시작 (StartType: Automatic)
- 콘솔 창 없이 백그라운드 실행
- Windows 이벤트 로그 및 파일 로그 지원
- `hyper-nat status` 명령으로 실행 중 상태 확인 가능

---

## 아키텍처

### 트리플 레이어 캡처 방식

외부 라이브러리의 한계로 인해 자체 WinDivert 래퍼를 구현하고, 트리플 레이어 캡처 방식을 채택했습니다.

```
┌─────────────────────────────────────────────────────────────────┐
│                        WinDivert                                │
├─────────────────────────────────────────────────────────────────┤
│  Outbound Handle          │  ICMP Handle          │  Inbound   │
│  (LayerNetworkForward)    │  (LayerNetworkForward)│  Handle    │
│  Priority: 0              │  Priority: 2          │  (Network) │
│  TCP/UDP only             │  ICMP Echo Request    │  Priority:1│
│                           │                       │            │
│  Filter:                  │  Filter:              │  Filter:   │
│  ip.SrcAddr in internal   │  icmp.Type == 8       │  !outbound │
│  and (tcp or udp)         │  and ip.SrcAddr in    │  and DstIP │
│                           │  internal             │  == NAT IP │
│                           │  and DstAddr != NAT IP│            │
├───────────────────────────┴───────────────────────┴────────────┤
│                                                                 │
│  VM (172.17.240.21)  ──SNAT──▶  NAT IP (192.168.45.57)         │
│                      ◀──DNAT──                                  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**왜 트리플 레이어인가?**
- `Outbound Handle (LayerNetworkForward)`: VM에서 나가는 TCP/UDP 패킷 캡처
- `ICMP Handle (LayerNetworkForward)`: VM에서 나가는 ICMP 패킷 캡처 (별도 핸들 필요)
  - NAT IP(호스트 자신)로 가는 ICMP는 필터에서 제외 (캡처하면 재주입 문제 발생)
- `Inbound Handle (LayerNetwork)`: 외부에서 NAT IP로 들어오는 응답 패킷 캡처
- ICMP는 TCP/UDP와 다른 핸들로 처리해야 송신 시 올바른 핸들 사용 가능

### 자체 WinDivert 래퍼

외부 라이브러리(godivert, go-windivert2)의 빌드 문제와 API 불일치로 인해 자체 래퍼를 구현:

```
windivert/
├── windivert.go          # 타입 정의, DLL 로딩
└── windivert_windows.go  # Windows 전용 syscall 구현
```

**주요 API:**
- `Open(filter, layer, priority, flags)` - 핸들 열기
- `Close()` - 핸들 닫기
- `Recv()` - 패킷 수신 (블로킹)
- `Send(packet)` - 패킷 송신
- `CalcChecksums()` - 체크섬 재계산

### 프로젝트 구조

```
hyper-nat/
├── CLAUDE.md                 # 개발 가이드 (이 파일)
├── README.md                 # 사용자 문서
├── go.mod
├── go.sum
├── hyper-nat.exe             # 빌드된 실행 파일
├── WinDivert.dll             # WinDivert 라이브러리
├── WinDivert64.sys           # WinDivert 드라이버
├── cmd/
│   ├── hyper-nat/
│   │   └── main.go           # CLI 진입점
│   └── test-capture/
│       └── main.go           # 패킷 캡처 테스트 도구
├── config/
│   ├── config.go             # 설정 파싱 및 필터 생성
│   ├── config_test.go
│   └── watcher.go            # 설정 파일 핫 리로드
├── ipc/
│   ├── server.go             # IPC 서버/클라이언트
│   └── server_test.go
├── configs/
│   └── hyper-nat.yaml        # 설정 파일
├── nat/
│   ├── engine.go             # NAT 엔진 (트리플 레이어 캡처)
│   ├── rules.go              # 규칙 매칭
│   ├── table.go              # 연결 추적 테이블
│   └── table_test.go
├── packet/
│   ├── modifier.go           # NAT 적용 (IP/포트/ICMP ID 변환)
│   ├── modifier_test.go      # 패킷 수정 테스트
│   ├── parser.go             # IPv4/TCP/UDP/ICMP 파싱
│   └── parser_test.go        # 패킷 파싱 테스트
├── scripts/
│   └── build.ps1             # 빌드 스크립트
├── service/
│   └── service_windows.go    # Windows 서비스 지원
└── windivert/
    ├── windivert.go          # 공통 타입 및 DLL 로딩
    └── windivert_windows.go  # Windows syscall 구현
```

---

## 테스트 환경

### 네트워크 구성 (테스트 완료)

```
┌──────────────────┐     ┌─────────────────────────────────────────┐
│   MacBook Pro    │     │           Windows 11 Host               │
│  192.168.45.152  │     │  External: 192.168.45.57                │
│                  │────▶│  Hyper-V Switch: 172.17.240.1           │
│                  │     │                                         │
│                  │     │  ┌─────────────────────────────────┐   │
│                  │     │  │  Ubuntu VM (172.17.240.21)      │   │
│                  │     │  │  Gateway: 172.17.240.1          │   │
│                  │     │  └─────────────────────────────────┘   │
└──────────────────┘     └─────────────────────────────────────────┘
```

### 설정 파일 (configs/hyper-nat.yaml)

```yaml
nat_ip: 192.168.45.57
internal_network: 172.17.240.0/24
rules:
  - name: "Host Network"
    destination: 192.168.45.0/24
    action: bypass
  - name: "Internet"
    destination: 0.0.0.0/0
    action: nat
```

### 테스트 방법

```powershell
# 1. 관리자 권한 PowerShell에서 hyper-nat 실행
cd C:\path\to\hyper-nat
.\hyper-nat.exe -config configs\hyper-nat.yaml -verbose

# 2. VM에서 인터넷 연결 테스트
ssh root@172.17.240.21
curl -s -o /dev/null -w "%{http_code}" https://www.google.com  # 200 출력 확인
curl ifconfig.me  # NAT IP의 외부 IP 출력 확인

# 3. Ctrl+C로 종료 (정상 종료 확인)
```

---

## 해결된 버그

### 1. net.IP 참조 버그 (2025-01-29)

**문제:** 연결 추적 테이블에서 IP 주소가 모두 동일한 값을 가리킴

**원인:** `net.IP`는 슬라이스이므로 패킷 데이터의 동일 메모리를 참조

**해결:** `nat/table.go`의 `Create()` 함수에서 IP 주소를 복사
```go
internalIPCopy := make(net.IP, len(intIP))
copy(internalIPCopy, intIP)
```

### 2. Graceful Shutdown 데드락 (2025-01-30)

**문제:** Ctrl+C 시 종료 메시지 출력 후 프로세스가 멈춤

**원인:** `Recv()` 함수가 mutex 잠금을 유지한 채 블로킹 → `Close()`가 같은 mutex를 요청하여 데드락

**해결:** `windivert/windivert_windows.go`의 `Recv()` 함수에서 mutex 제거
```go
// Recv receives a packet
// Note: No mutex lock here to allow Close() to interrupt blocking Recv()
func (h *Handle) Recv() (*Packet, error) {
    // mutex 없이 직접 syscall
}
```

### 3. ICMP 호스트 ping 실패 (2025-01-30)

**문제:** VM에서 호스트 PC(NAT IP)로 ping 시 응답 없음 (다른 호스트 네트워크 PC는 정상)

**원인:** LayerNetworkForward에서 캡처한 패킷을 재주입하면 목적지가 호스트 자신일 때 전달 안됨

**해결:** `config/config.go`의 ICMP 필터에서 NAT IP 제외
```go
// NAT IP로 가는 ICMP는 캡처하지 않음 (호스트 자신이 처리)
icmpOutboundFilter = fmt.Sprintf(
    "icmp.Type == 8 and ip.SrcAddr >= %s and ip.SrcAddr <= %s and ip.DstAddr != %s",
    startIP.String(), endIP.String(), c.NATIP.String(),
)
```

---

## 실행 방법

### 포그라운드 실행

```powershell
# 1. 빌드
go build -o hyper-nat.exe ./cmd/hyper-nat

# 2. WinDivert 파일 배치
# WinDivert.dll, WinDivert64.sys를 hyper-nat.exe와 같은 디렉토리에 배치
# 다운로드: https://reqrypt.org/windivert.html

# 3. 설정 파일 편집
notepad configs/hyper-nat.yaml

# 4. 관리자 권한으로 실행
.\hyper-nat.exe -config configs/hyper-nat.yaml -verbose

# 5. 로그 파일과 함께 실행 (stdout + 파일 동시 출력)
.\hyper-nat.exe -config configs/hyper-nat.yaml -logfile logs/hyper-nat.log -verbose

# 6. 종료: Ctrl+C
```

### 서비스 실행

```powershell
# 1. 서비스 설치 (관리자 권한 필수, 절대 경로 권장)
.\hyper-nat.exe install -config C:\hyper-nat\configs\hyper-nat.yaml -logfile C:\hyper-nat\logs\hyper-nat.log

# 2. 서비스 시작
.\hyper-nat.exe start

# 3. 상태 확인
.\hyper-nat.exe status

# 4. 서비스 중지
.\hyper-nat.exe stop

# 5. 서비스 제거
.\hyper-nat.exe uninstall
```

---

## 개발 시 주의사항

1. **관리자 권한**: WinDivert는 커널 드라이버이므로 항상 관리자 권한으로 실행

2. **드라이버 파일**: WinDivert.dll과 WinDivert64.sys가 실행 파일과 같은 디렉토리에 있어야 함

3. **Recv() 블로킹**: `Recv()`는 블로킹 호출이므로 종료 시 `Close()`로 핸들을 닫아야 함

4. **IP 슬라이스 복사**: `net.IP`는 슬라이스이므로 저장 시 반드시 복사해야 함

5. **체크섬**: 패킷 수정 후 `CalcChecksums()` 호출 필수 (안하면 패킷 드롭)

6. **필터 정확성**: WinDivert 필터가 잘못되면 무관한 패킷까지 가로채서 시스템 불안정 유발

---

## 참조 문서

- WinDivert 공식 문서: https://reqrypt.org/windivert-doc.html
- WinDivert 필터 문법: https://reqrypt.org/windivert-doc.html#filter_language
- WinDivert 다운로드: https://reqrypt.org/windivert.html
