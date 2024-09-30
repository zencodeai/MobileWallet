from dataclasses import dataclass, field


@dataclass
class OBPRouting:
    # Routing object class
    scheme: str
    address: str


@dataclass
class OBPBankAttribute:
    # Bank attribute object
    name: str
    value: str


@dataclass
class OBPBank:
    # Bank object class
    id: str
    short_name: str
    full_name: str
    logo: str | None
    website: str | None
    bank_routings: list[OBPRouting] = field(default_factory=list)
    attributes: list[OBPRouting] = field(default_factory=list)


@dataclass
class OBPBankList:
    # Bank list object class
    banks: list[OBPBank] = field(default_factory=list)
