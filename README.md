# 냥혼석 세공 전략실

기존 MCP/Discord 백엔드를 단일 정적 웹사이트로 교체한 저장소입니다.

## 실행 및 배포
- Docker 이미지: `nginx:alpine`
- 웹 포트: `10000`
- 정적 페이지: `index.html`
- 상태 확인: `/healthz`

Render의 기존 `dino-web` 서비스가 이 저장소의 `main` 브랜치를 자동 배포합니다.
