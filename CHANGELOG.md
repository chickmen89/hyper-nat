# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.3.0] - 2026-02-02

### Added
- 포트 포워딩 (DNAT) 지원
  - 외부 포트를 내부 VM의 IP/포트로 매핑
  - `port_forward` 설정 섹션 추가
- CLI 상태 조회 명령 (`hyper-nat status`)
  - 실시간 연결 테이블 조회 (SNAT/DNAT 모두 지원)
  - 패킷 통계 표시
  - IPC 서버 (TCP 포트 47847)
- 설정 파일 핫 리로드
  - 규칙 변경 시 재시작 없이 적용
  - 5초 간격으로 설정 파일 모니터링
- 에러 복구 로직 강화
  - 지수 백오프 재시도 (최대 5회)
  - 복구된 에러 카운트 통계
- TCP ESTABLISHED 연결 타임아웃 (2시간)
  - 장시간 운영 시 메모리 누수 방지
- 도움말 명령 (`hyper-nat help`)

### Changed
- 버전 0.2.0 → 0.3.0

## [0.2.0] - 2025-01-30

### Added
- ICMP NAT 지원 (Echo Request/Reply)
  - VM에서 외부로 ping 가능
  - ICMP Identifier를 NAT ID로 매핑하여 추적

### Fixed
- Graceful shutdown 데드락 해결
  - `Recv()` 함수에서 mutex 제거하여 `Close()` 호출 시 즉시 종료
- ICMP 호스트 ping 실패 수정
  - NAT IP로 가는 ICMP는 필터에서 제외 (호스트가 직접 처리)

### Changed
- 듀얼 레이어 → 트리플 레이어 캡처 방식으로 변경
  - Outbound Handle (TCP/UDP)
  - ICMP Handle (ICMP Echo Request)
  - Inbound Handle (응답 패킷)

## [0.1.0] - 2025-01-29

### Added
- 초기 MVP 릴리스
- TCP/UDP NAT 지원
- 목적지 기반 규칙 매칭 (bypass/nat)
- 연결 추적 테이블 (Connection Tracking)
- TCP 상태 추적 (SYN_SENT → ESTABLISHED → TIME_WAIT)
- 자체 WinDivert Go 래퍼 구현
  - 외부 라이브러리(godivert, go-windivert2) 빌드 문제 해결
- YAML 설정 파일 지원
- CLI 옵션 (`-config`, `-verbose`, `-version`)

### Fixed
- net.IP 참조 버그 해결
  - 연결 추적 테이블에서 IP 주소 저장 시 슬라이스 복사
