"""The classifier's preprocessing, for the training scripts. The code lives in
app/services/features.py so the deployed service runs exactly what the model was trained on;
see that module for what preprocess() does."""

from app.services.features import (
    CHAR_NGRAMS,
    FEATURES_VERSION,
    WORD_NGRAMS,
    char_ngrams,
    preprocess,
    url_token,
    word_ngrams,
    words,
)

__all__ = [
    "CHAR_NGRAMS",
    "FEATURES_VERSION",
    "WORD_NGRAMS",
    "char_ngrams",
    "preprocess",
    "url_token",
    "word_ngrams",
    "words",
]
