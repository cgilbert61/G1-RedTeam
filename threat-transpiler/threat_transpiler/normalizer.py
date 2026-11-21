import re
import base64
import unicodedata
from typing import List

class ThreatNormalizer:
    """
    Canonicalization pipeline that strips adversarial evasion techniques such as
    zero-width spaces, base64 obfuscation wrappers, Unicode homoglyphs, and leetspeak.
    """

    # Common Cyrillic and Greek characters lookalikes mapped to Latin equivalents
    HOMOGLYPH_MAP = {
        # Cyrillic lookalikes
        0x0430: 'a', 0x0410: 'A',  # а / А
        0x0435: 'e', 0x0415: 'E',  # е / Е
        0x043e: 'o', 0x041e: 'O',  # о / О
        0x0440: 'r', 0x0420: 'R',  # р / Р
        0x0441: 'c', 0x0421: 'C',  # с / С
        0x0443: 'y', 0x0423: 'Y',  # у / У
        0x0455: 's', 0x0405: 'S',  # ѕ / Ѕ
        0x0456: 'i', 0x0406: 'I',  # і / І
        0x0458: 'j', 0x0408: 'J',  # ј / Ј
        0x0445: 'x', 0x0425: 'X',  # х / Х
        0x043c: 'm', 0x041c: 'M',  # м / М
        0x043d: 'h', 0x041d: 'H',  # н / Н
        0x043a: 'k', 0x041a: 'K',  # к / К
        # Greek lookalikes
        0x03b1: 'a', 0x0391: 'A',  # α / Α
        0x03b2: 'b', 0x0392: 'B',  # β / Β
        0x03b5: 'e', 0x0395: 'E',  # ε / Ε
        0x03bf: 'o', 0x039f: 'O',  # ο / Ο
        0x03c1: 'r', 0x03a1: 'R',  # ρ / Ρ
        0x03c4: 't', 0x03a4: 'T',  # τ / Τ
        0x03ba: 'k', 0x039a: 'K',  # κ / Κ
        0x03bd: 'v', 0x039d: 'N',  # ν / Ν
        0x03c7: 'x', 0x03a7: 'X',  # χ / Χ
        0x03b7: 'h', 0x0397: 'H',  # η / Η
        0x03b9: 'i', 0x0399: 'I',  # ι / Ι
        0x03bc: 'm', 0x039c: 'M',  # μ / Μ
    }

    # Leetspeak translation table
    LEET_MAP = {
        '1': 'i', '!': 'i', '|': 'i',
        '3': 'e',
        '4': 'a', '@': 'a',
        '0': 'o',
        '5': 's', '$': 's',
        '7': 't', '+': 't',
        '8': 'b',
        '9': 'g',
        '(': 'c', '<': 'c'
    }

    # Zero-width spaces and other invisible/formatting characters
    INVISIBLE_CHARS = re.compile(
        r'[\u200b-\u200d\u200e\u200f\ufeff\u202a-\u202e\u2060\u180e\u2000-\u200a]'
    )

    @classmethod
    def strip_invisible_characters(cls, text: str) -> str:
        """Removes zero-width spaces, BOMs, and directional formatting overrides."""
        return cls.INVISIBLE_CHARS.sub('', text)

    @classmethod
    def decode_base64_wrappers(cls, text: str) -> str:
        """
        Detects base64-encoded strings or wrappers (e.g. base64:aGVsbG8=)
        and recursively decodes them if printable.
        """
        # Match standard base64 pattern wrapper: base64(content) or base64:content
        match = re.search(r'(?:base64[:(])\s*([A-Za-z0-9+/=]+)\s*\)?', text, re.IGNORECASE)
        if match:
            b64_candidate = match.group(1)
            try:
                decoded_bytes = base64.b64decode(b64_candidate, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='strict')
                # If decoded successfully, replace the wrapper with the decoded text and run recursively
                replaced = text.replace(match.group(0), decoded_str)
                return cls.decode_base64_wrappers(replaced)
            except Exception:
                pass
        
        # If no wrapper was found or decoding failed, try checking if the whole text is valid base64
        # (Must be at least 8 chars, multiple of 4, with base64 character set)
        cleaned_text = text.strip()
        if len(cleaned_text) >= 8 and len(cleaned_text) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]+$', cleaned_text):
            try:
                decoded_bytes = base64.b64decode(cleaned_text, validate=True)
                decoded_str = decoded_bytes.decode('utf-8', errors='strict')
                # Check if decoded string is mostly printable text
                if all(c.isprintable() or c.isspace() for c in decoded_str):
                    return cls.decode_base64_wrappers(decoded_str)
            except Exception:
                pass

        return text

    @classmethod
    def fold_homoglyphs(cls, text: str) -> str:
        """
        Applies standard Unicode NFKC normalization followed by our custom
        Cyrillic/Greek-to-Latin homoglyph mapping table.
        """
        # Step 1: Normalize via NFKC (decomposes accents, normalizes character variants)
        text = unicodedata.normalize("NFKC", text)
        
        # Step 2: Apply custom homoglyph translation table
        return text.translate(cls.HOMOGLYPH_MAP)

    @classmethod
    def resolve_leetspeak(cls, text: str) -> str:
        """
        Folds common leetspeak substitutions back to their base alphabetical equivalents.
        """
        # Map digits and '@'
        digit_map = {
            '1': 'i', '3': 'e', '4': 'a', '0': 'o', '5': 's', '7': 't', '8': 'b', '9': 'g', '@': 'a'
        }
        text = "".join(digit_map.get(c, c) for c in text)
        
        # Contextual replacements for punctuation symbols to prevent trailing punctuation collision
        # $ -> s
        text = re.sub(r'(?<=\w)\$(?=\w)|(?<=\w)\$|\$(?=\w)', 's', text)
        # ! -> i (only if surrounded by alphanumeric)
        text = re.sub(r'(?<=[a-zA-Z0-9])!(?=[a-zA-Z0-9])', 'i', text)
        # + -> t (only if surrounded by alphanumeric)
        text = re.sub(r'(?<=[a-zA-Z0-9])\+(?=[a-zA-Z0-9])', 't', text)
        # | -> i (only if surrounded by alphanumeric)
        text = re.sub(r'(?<=[a-zA-Z0-9])\|(?=[a-zA-Z0-9])', 'i', text)
        # ( -> c, < -> c (only if adjacent to alphanumeric)
        text = re.sub(r'\((?=[a-zA-Z0-9])|(?<=[a-zA-Z0-9])\(', 'c', text)
        text = re.sub(r'<(?=[a-zA-Z0-9])|(?<=[a-zA-Z0-9])<', 'c', text)
        
        return text

    @classmethod
    def normalize_text(cls, text: str) -> str:
        """
        Runs the complete canonicalization pipeline in order.
        """
        if not text:
            return ""
        
        # 1. Base64 wrappers check
        text = cls.decode_base64_wrappers(text)
        # 2. Strip invisible characters
        text = cls.strip_invisible_characters(text)
        # 3. Fold homoglyphs
        text = cls.fold_homoglyphs(text)
        # 4. Fold leetspeak
        text = cls.resolve_leetspeak(text)
        # 5. Clean whitespaces & lower
        text = " ".join(text.strip().split()).lower()
        
        return text

    @classmethod
    def tokenize(cls, text: str) -> List[str]:
        """
        Splits canonicalized text into a list of alphanumeric tokens.
        """
        canonical = cls.normalize_text(text)
        # Match alphanumeric sequences
        tokens = re.findall(r'\b\w+\b', canonical)
        return tokens
