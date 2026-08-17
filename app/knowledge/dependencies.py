from functools import lru_cache

from app.knowledge.attack_repository import (
    AttackKnowledgeRepository,
)


@lru_cache
def get_attack_repository() -> (
    AttackKnowledgeRepository
):
    return AttackKnowledgeRepository.from_file()