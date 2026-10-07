"""Imports every ORM model so Alembic autogenerate and metadata.create_all see them."""

from app.audit.models import AuditLog
from app.auth.models import RefreshToken
from app.core.db import Base
from app.tenants.models import Tenant
from app.users.models import Membership, User

__all__ = ["AuditLog", "Base", "Membership", "RefreshToken", "Tenant", "User"]
from app.hunts.models import Finding, Hunt, HuntNote, QueryHistory, SavedQuery  # noqa: E402

__all__ += ["Finding", "Hunt", "HuntNote", "QueryHistory", "SavedQuery"]
from app.assets.models import Asset  # noqa: E402
from app.cases.models import (  # noqa: E402
    Case,
    CaseActivity,
    CaseAsset,
    CaseCounter,
    CaseEvidence,
    CaseIoc,
    CaseReport,
)
from app.datasources.models import DataSource  # noqa: E402

__all__ += [
    "Asset",
    "Case",
    "CaseActivity",
    "CaseAsset",
    "CaseCounter",
    "CaseEvidence",
    "CaseIoc",
    "CaseReport",
    "DataSource",
]
from app.intel.models import IntelEntity, IntelObservation, IntelProvider, IntelRelation  # noqa: E402
from app.mitre.models import MitreMapping, MitreTactic, MitreTechnique  # noqa: E402

__all__ += [
    "IntelEntity",
    "IntelObservation",
    "IntelProvider",
    "IntelRelation",
    "MitreMapping",
    "MitreTactic",
    "MitreTechnique",
]
