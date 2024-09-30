from dataclasses import dataclass


@dataclass
class OBPEntitlement:
	# Entitlement object class
	entitlement_id: str
	role_name: str
	bank_id: str
