from .strip_docstrings import StripDocstrings
from .rename_identifiers import RenameIdentifiers
from .encode_constants import EncodeConstants
from .getattr_attributes import GetattrAttributes
from .insert_dummy_comments import InsertDummyComments

__all__ = [
    "StripDocstrings",
    "RenameIdentifiers",
    "EncodeConstants",
    "GetattrAttributes",
    "InsertDummyComments",
]
