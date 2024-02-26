from __future__ import annotations


def underscore_to_camelcase(word, initial_capital=False):
    """Transform a word to camelCase."""
    words = [x.capitalize() or "_" for x in word.split("_")]
    if not initial_capital:
        words[0] = words[0].lower()

    return "".join(words)
