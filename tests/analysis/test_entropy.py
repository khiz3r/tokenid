from tokenid.analysis.entropy import compute_entropy


def test_entropy_separates_theoretical_observed_and_estimated():
    stats = compute_entropy("550e8400-e29b-41d4-a716-446655440000")
    assert stats.actual_entropy_bits is None
    assert stats.theoretical_entropy_bits >= stats.observed_entropy_bits
    assert stats.observed_entropy_bits >= 0
    assert stats.estimated_entropy_bits >= 0
    assert any("not proof" in note for note in stats.notes)


def test_single_character_token_is_flagged():
    stats = compute_entropy("aaaaaaaa")
    assert stats.unique_chars == 1
    assert stats.shannon_entropy_per_char == 0
    assert any("placeholder" in note for note in stats.notes)


def test_charset_classes():
    assert compute_entropy("abcdef0123456789").charset_class == "hex"
    assert compute_entropy("123456789").charset_class == "digits"
    assert compute_entropy("01ARZ3NDEKTSV4RRFFQ69G5FAV").charset_class == "crockford-base32"
    assert compute_entropy("550e8400-e29b-41d4-a716-446655440000").charset_class == "uuid-hex"


def test_short_sample_note():
    stats = compute_entropy("abc")
    assert any("Short samples" in note for note in stats.notes)
