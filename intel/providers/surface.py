"""Compatibility guard for the removed intelligence surface provider."""


class SurfaceProvider:
    """Fail closed: SRC target GET discovery moved to ``src_surface.py``."""

    def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        del args, kwargs
        raise RuntimeError("surface_provider_moved_to_pentest_agent_src_surface")
