"""Single source of default role definitions; constructing these writes nothing."""

from .role_global_admin import build as role_global_admin
from .role_global_maintainer import build as role_global_maintainer
from .role_global_instructor import build as role_global_instructor
from .role_global_course_author import build as role_global_course_author
from .role_global_user import build as role_global_user


def desired_roles():
    roles = [
        role_global_admin(),
        role_global_maintainer(),
        role_global_instructor(),
        role_global_course_author(),
        role_global_user(),
    ]
    for role in roles:
        role.rights = role.rights.model_dump()
    return roles
