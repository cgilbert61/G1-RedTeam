from typing import List, Dict, Union, Any, Optional
from pydantic import BaseModel, Field, field_validator

class IRPayload(BaseModel):
    """
    Intermediate Representation (IR) Schema for normalized prompt injection threats.
    """
    threat_id: str = Field(description="Unique identifier for the threat signature.")
    category: str = Field(description="The threat category, e.g., 'jailbreak', 'smuggling', 'hate_speech'.")
    vulnerability_id: Optional[str] = Field(
        default=None,
        description="Optional canonical VulnerabilityId for 8-framework compliance mapping.",
    )
    canonical_text: str = Field(description="The normalized and canonicalized text of the threat.")
    tokens: List[str] = Field(default_factory=list, description="Extracted token sequences of interest.")
    centroids: List[float] = Field(default_factory=list, description="Semantic embedding centroid vector coordinates.")
    constraints: Dict[str, Union[str, int, float, List[Any]]] = Field(
        default_factory=dict, 
        description="Structural parameters or boundaries, e.g., {'max_length': 100, 'forbidden_keywords': ['admin']}."
    )
    metadata: Dict[str, Union[str, int, float, List[Any], Dict[str, Any]]] = Field(
        default_factory=dict,
        description="Extensible metadata schema (timestamps, confidence score, source data)."
    )

    @field_validator("threat_id", "category")
    @classmethod
    def must_not_be_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Field cannot be empty or whitespace-only.")
        return value.strip()

    @field_validator("centroids")
    @classmethod
    def validate_centroids(cls, value: List[float]) -> List[float]:
        for val in value:
            if not isinstance(val, (int, float)):
                raise ValueError("Centroid values must be numeric float coordinates.")
        return [float(x) for x in value]
