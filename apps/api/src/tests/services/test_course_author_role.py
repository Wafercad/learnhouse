"""The seeded Course Author role (id 5).

Wafercad's platform admin authors the catalogue; its instructors must not. That
split is why this role exists instead of reusing Instructor(3), which is
own-scoped on courses and cannot edit a chapter at all once it is created.

Asserted on the seed definition rather than through the API: the role has to be
the same in every deployment for an integration to name it without per-org
configuration, and that is a property of the seed.
"""

import re
from pathlib import Path

from src.security.rbac.constants import (
    ADMIN_ROLE_ID,
    COURSE_AUTHOR_ROLE_ID,
    MAINTAINER_ROLE_ID,
)
from src.services.admin.admin import _role_priority

_SETUP = Path(__file__).resolve().parents[2] / "services" / "setup" / "setup.py"


def _granted(role_uuid: str) -> dict[str, set[str]]:
    """The actions each resource grants, read off the seed definition."""
    source = _SETUP.read_text()
    start = source.index(f'role_uuid="{role_uuid}"')
    end = source.find("creation_date=", start)
    rights: dict[str, set[str]] = {}
    resource = None
    for line in source[start:end].splitlines():
        line = line.strip()
        opened = re.match(r"([a-z_]+)=(Permissions?WithOwn|Permission|DashboardPermission)\(", line)
        if opened:
            resource = opened.group(1)
            rights[resource] = set()
            continue
        action = re.match(r"action_([a-z_]+)=(True|False),?", line)
        if action and resource and action.group(2) == "True":
            rights[resource].add(action.group(1))
    return rights


def test_course_author_owns_every_course_resource_outright():
    """Org-wide, not own-scoped. A platform author edits the catalogue, which
    means courses somebody else created."""
    rights = _granted("role_global_course_author")

    assert {"create", "read", "update", "delete"} <= rights["courses"]
    # The course's CONTENT, which is the part Instructor cannot touch at all.
    assert {"create", "read", "update", "delete"} <= rights["coursechapters"]
    assert {"create", "read", "update", "delete"} <= rights["activities"]
    assert {"create", "read", "update", "delete"} <= rights["assignments"]
    # Artwork and the files behind lessons travel with the course.
    assert {"create", "read", "update", "delete"} <= rights["media"]
    assert {"create", "read", "update", "delete"} <= rights["folders"]


def test_course_author_governs_nothing():
    """Authoring is not administration. Granting `roles` in particular would let
    the role rewrite its own rights."""
    rights = _granted("role_global_course_author")

    assert rights["users"] == set()
    assert rights["roles"] == set()
    assert rights["organizations"] == set()
    assert rights["usergroups"] == {"read"}


def test_instructor_still_cannot_author():
    """The requirement this role exists to avoid breaking: a Wafercad instructor
    maps to the read-only learner and must stay unable to edit a course."""
    instructor = _granted("role_global_instructor")

    assert "update" not in instructor["courses"]
    assert "delete" not in instructor["courses"]
    assert instructor["coursechapters"] == {"create", "read"}


def test_an_api_token_may_assign_it():
    """The whole point. Admin(1) and Maintainer(2) are refused to API tokens by
    id, and anything of higher priority than the token's creator is refused too.
    Course Author sits level with Instructor, so the provisioning integration
    can grant it."""
    assert COURSE_AUTHOR_ROLE_ID not in {ADMIN_ROLE_ID, MAINTAINER_ROLE_ID}
    assert _role_priority(COURSE_AUTHOR_ROLE_ID) == _role_priority(3)
