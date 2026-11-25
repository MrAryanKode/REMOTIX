
# REMOTIX

### Your PC. Anywhere. Anytime.

REMOTIX is a cross-platform remote desktop and device-control platform.

## Supported Platforms

- Windows 11
- Linux
- Android
- iOS
- Google Chrome

## Architecture

| Component | Technology |
|---|---|
| Host Agent | Rust |
| Mobile App | Flutter |
| Desktop UI | Tauri |
| Browser Extension | TypeScript |
| Signalling | Rust + WebSocket |
| API | FastAPI |
| Streaming | WebRTC |
| Database | PostgreSQL |
| Relay | coturn |

## Project Structure

- apps/ - User-facing applications
- agents/ - Native remote host
- services/ - Backend services
- packages/ - Shared protocols
- infrastructure/ - Deployment
- docs/ - Technical documentation

## Development Status

Phase 1: Environment and repository setup.

## Security

Remote access is restricted to explicitly paired and
authorized devices. All remote sessions must use
authenticated, encrypted connections.
