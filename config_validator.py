from pydantic import BaseModel, Field, ValidationError
from pathlib import Path
import json
from typing import List, Optional

class ConfigModel(BaseModel):
    bot_token: str = Field(..., min_length=1)
    chat_id: str = Field(..., min_length=1)
    ignored_hostnames: List[str] = Field(default_factory=list)
    ignored_macs: List[str] = Field(default_factory=list)

def load_and_validate_config(config_path: Path) -> Optional[ConfigModel]:
    if not config_path.exists():
        return None
    
    try:
        with open(config_path) as f:
            data = json.load(f)
        return ConfigModel(**data)
    except (json.JSONDecodeError, ValidationError, IOError) as e:
        print(f"Error loading configuration: {e}")
        return None
