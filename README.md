# ZeroGraph

ZeroGraph maps the non-human identities and AI agents in your AWS accounts, and the data
each one can reach. It uses CloudTrail to show which granted access is never used, and
proposes least-privilege fixes as draft pull requests for you to review. It is read-only:
it never changes your cloud.

## Quick start

Requires Docker Compose. From the repository root:

```sh
python3 deploy/init_env.py
docker compose up --build -d
```

Then open http://localhost:3100.

## Docs

- [Deploying and operating](docs/operations.md)
- [Security model](docs/security-model.md)
- [Usage evidence (CloudTrail)](docs/usage-evidence.md)
- [Proposals and pull requests](docs/proposals.md)
- [AWS setup](docs/aws-qualification.md)

## Development

```sh
python3.12 -m venv backend/.venv
backend/.venv/bin/pip install -r backend/requirements-dev.lock -e backend
(cd frontend && npm ci)
make test
```
