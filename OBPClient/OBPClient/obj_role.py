from dataclasses import dataclass, field


@dataclass
class OBPRole:
	# Role object class
	role: str
	requires_bank_id: bool


@dataclass
class OBPRoleList:
	# List of roles as returned by the /roles API
	roles: list[OBPRole] = field(default_factory=list)
