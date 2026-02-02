# 포트 포워딩 (DNAT) 설계

## 개요
외부에서 NAT IP의 특정 포트로 들어오는 트래픽을 내부 VM으로 전달하는 기능.

## 설정 파일 방식

### YAML 구조
```yaml
# 기존 설정
nat_ip: 192.168.45.57
internal_network: 172.17.240.0/24
rules:
  - name: "인터넷"
    destination: 0.0.0.0/0
    action: nat

# 신규: 포트 포워딩
port_forward:
  - name: "Web Server"
    protocol: tcp          # tcp 또는 udp
    external_port: 8080    # NAT IP에서 수신할 포트
    internal_ip: 172.17.240.21
    internal_port: 80      # 내부 VM 포트 (생략 시 external_port와 동일)
    
  - name: "SSH"
    protocol: tcp
    external_port: 2222
    internal_ip: 172.17.240.21
    internal_port: 22
    
  - name: "DNS"
    protocol: udp
    external_port: 53
    internal_ip: 172.17.240.100
    internal_port: 53
```

### 동작 방식
1. 외부 → NAT IP:8080 (TCP) 패킷 수신
2. DNAT 적용: 목적지를 172.17.240.21:80으로 변경
3. 응답 패킷: 출발지를 NAT IP:8080으로 복원

## CLI 명령 방식

### 명령어
```bash
# 포트 포워딩 목록 조회
hyper-nat forward list

# 포트 포워딩 추가
hyper-nat forward add --name "Web" --proto tcp --port 8080 --to 172.17.240.21:80

# 단축 형식
hyper-nat forward add tcp/8080:172.17.240.21:80

# 포트 포워딩 제거
hyper-nat forward remove 8080
hyper-nat forward remove --name "Web"
```

### IPC 프로토콜 확장
```json
// Request
{"action": "forward_add", "rule": {"name": "Web", "protocol": "tcp", "external_port": 8080, "internal_ip": "172.17.240.21", "internal_port": 80}}

// Response
{"success": true, "message": "Port forward added"}

// List
{"action": "forward_list"}

// Response
{"success": true, "forwards": [...]}
```

## 구현 계획

### Phase 1: 설정 파일 기반 DNAT
1. `config/config.go` - PortForward 구조체 추가
2. `nat/dnat.go` - DNAT 테이블 및 로직
3. `nat/engine.go` - Inbound 핸들러에 DNAT 처리 추가
4. WinDivert 필터 수정 - 포트 포워딩 대상 포트 캡처

### Phase 2: CLI 동적 관리
1. `cmd/hyper-nat/main.go` - forward 서브커맨드 추가
2. `ipc/server.go` - forward 관련 핸들러 추가
3. 런타임 규칙 추가/삭제 지원

### Phase 3: 영속성
1. CLI로 추가한 규칙을 설정 파일에 저장
2. 또는 별도 상태 파일 (state.json) 관리

## WinDivert 필터 수정

### 현재 Inbound 필터
```
!outbound and ip.DstAddr == {NAT_IP} and (
  (tcp.DstPort >= 40000 and tcp.DstPort <= 60000) or
  (udp.DstPort >= 40000 and udp.DstPort <= 60000) or
  (icmp.Type == 0)
)
```

### 포트 포워딩 추가 후
```
!outbound and ip.DstAddr == {NAT_IP} and (
  (tcp.DstPort >= 40000 and tcp.DstPort <= 60000) or
  (udp.DstPort >= 40000 and udp.DstPort <= 60000) or
  (icmp.Type == 0) or
  (tcp.DstPort == 8080) or  # 포트 포워딩
  (tcp.DstPort == 2222) or
  (udp.DstPort == 53)
)
```

## 연결 추적

### DNAT 테이블 구조
```go
type DNATEntry struct {
    Protocol     string    // "tcp" or "udp"
    ExternalPort uint16    // NAT IP에서 수신할 포트
    InternalIP   net.IP    // 내부 VM IP
    InternalPort uint16    // 내부 VM 포트
    Name         string    // 규칙 이름
}

type DNATTable struct {
    entries map[uint16]*DNATEntry  // key: external_port
    mu      sync.RWMutex
}
```

### 세션 추적
기존 NAT 테이블과 유사하게 연결별 상태 추적 필요:
- 외부 클라이언트 IP:Port → 내부 VM IP:Port 매핑
- 응답 패킷 역변환용

## 테스트 시나리오

1. **기본 TCP 포트 포워딩**
   - 외부에서 NAT_IP:8080 → VM:80 접속 테스트
   
2. **UDP 포트 포워딩**
   - DNS 쿼리 포워딩 테스트
   
3. **다중 클라이언트**
   - 여러 외부 클라이언트가 동시 접속
   
4. **Hot Reload**
   - 설정 파일 변경 시 포트 포워딩 규칙 즉시 적용

5. **CLI 동적 추가/삭제**
   - 런타임 중 규칙 변경
