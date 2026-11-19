import hashlib

from insidia.mask import mask


def _token(kind: str, secret: str) -> str:
    fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:8]
    return f"[{kind} len={len(secret)} fp={fingerprint}]"


def test_aws_key_is_masked_with_length_and_fingerprint() -> None:
    secret = "AKIAIOSFODNN7EXAMPLE"
    masked = mask(f"token {secret} end")
    assert secret not in masked
    assert masked == f"token {_token('AWS_ACCESS_KEY', secret)} end"


def test_password_assignment_masks_only_the_value() -> None:
    secret = "hunter2"
    assert mask(f"password={secret}") == f"password={_token('PASSWORD', secret)}"
    assert mask("password=hunter") == f"password={_token('PASSWORD', 'hunter')}"
    assert mask(f'{{"api_key": "{secret}"}}') == f'{{"api_key": "{_token("API_KEY", secret)}"}}'
    assert mask("Choose a password.") == "Choose a password."


def test_authorization_header_masks_only_the_value() -> None:
    secret = "abcdefgh"
    assert mask(f"Authorization: Bearer {secret}") == (
        f"Authorization: Bearer {_token('AUTHORIZATION', secret)}"
    )
