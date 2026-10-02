"""Create local development secrets without overwriting existing configuration."""
import os
import secrets
from pathlib import Path

root = Path(__file__).resolve().parents[1]
target = root / ".env"
content = (root / ".env.example").read_text()
content = content.replace("replace-with-random-64-character-token", secrets.token_hex(32))
content = content.replace("replace-with-random-64-character-secret", secrets.token_hex(32))
content = content.replace("replace-with-random-password", secrets.token_hex(24))
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as stream:
    stream.write(content)
print("Created .env with local-only demo authentication. Do not use this configuration in production.")
