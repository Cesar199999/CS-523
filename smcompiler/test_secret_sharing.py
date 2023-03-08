from secret_sharing import (
    reconstruct_secret,
    share_secret,
)

num_shares = 31
# ==================== TEST ADDITION ====================


def test_add():
    assert reconstruct_secret(share_secret(15, num_shares)) == 15
