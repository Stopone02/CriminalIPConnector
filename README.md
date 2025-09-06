# Criminal IP Connector (OpenCTI) — Skeleton

이 저장소는 OpenCTI의 내부 enrichment 커넥터 구조를 참고하여 **Criminal IP 연동용 커넥터 뼈대**를 제공합니다.

## 기능 개요
- Criminal IP API(`/v1/ip/data`, `/v1/ip/summary`)를 호출하여 IP 관련 속성(평판 점수, 태그, ASN, 국가 등)을 수집
- **STIX 매핑 규칙 적용 → STIX 2.1 객체 생성** (IPv4-Addr, Indicator, Autonomous-System, Location)
- 현재는 **데모 모드**로 단일 IP를 조회하여 STIX Bundle(JSON)을 출력합니다. (OpenCTI로의 전송은 TODO)

## 디렉토리 구조
```
criminalip-connector/
├── __docs__/media/                 # 문서 미디어
├── src/
│   ├── config.yml.sample           # 설정 샘플
│   ├── config.yml                  # (직접 생성) 실제 설정
│   ├── requirements.txt            # 파이썬 의존성
│   └── criminalipImport.py         # 핵심 실행 로직
├── Dockerfile
├── docker-compose.yml
└── entrypoint.sh
```

## 설치 및 실행

### 1) 로컬 실행
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r src/requirements.txt

# 환경변수로 API Key 전달
export CRIMINALIP_TOKEN="YOUR_API_KEY"
export TEST_IP="8.8.8.8"  # 선택

# 설정 파일 준비 (옵션)
cp src/config.yml.sample src/config.yml
# 필요한 값 채우기 (OPENCTI_URL 등은 데모 모드에서는 사용 안함)

python src/criminalipImport.py
```
출력: STIX Bundle(JSON)

### 2) Docker 실행
```bash
# config.yml 생성 (필수)
cp src/config.yml.sample src/config.yml

# 환경변수로 API Key 주입
export CRIMINALIP_TOKEN="YOUR_API_KEY"
export TEST_IP="1.1.1.1"  # 선택

docker compose up --build
```

## STIX 변환 매핑 (요약)
| API 필드                    | STIX 객체           | STIX 속성/설명                            |
|----------------------------|---------------------|-------------------------------------------|
| `ip`                       | `IPv4-Addr`         | `value`                                   |
| `score.inbound/outbound`   | `Indicator`         | `labels`(inbound/outbound) + `confidence` |
| `tags.is_*`(VPN/TOR 등)    | `Indicator`         | `labels` (예: `VPN`, `TOR`, `PROXY`)      |
| `asn`                      | `Autonomous-System` | `number`                                  |
| `countryCode`              | `Location`          | `country`                                 |

## 데이터 흐름
```
[시작] docker-compose up
    ↓
[entrypoint.sh 실행]
    ↓
[criminalipImport.py 실행]
    ↓
[config.yml로부터 설정 로딩]
    ↓
[Criminal IP API 호출하여 Observable 관련 정보 수집]
    ↓
[수집된 정보 → STIX 매핑 규칙 적용 → STIX 포맷 변환]
    ↓
[OpenCTI API 또는 메시지 큐로 전송]   # TODO
    ↓
[OpenCTI UI에서 enrichment 결과 확인] # TODO
```

## OpenCTI 연동 가이드 (TODO)
- Python OpenCTI client를 사용하거나, 기존 Shodan 커넥터 코드 패턴을 참고하여 메시지 큐(RabbitMQ)로 전송
- `CONNECTOR_SCOPE`에 따라 지원 Observable 필터링
- 에러/재시도/Rate-Limit 처리
