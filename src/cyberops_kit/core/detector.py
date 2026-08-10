"""Technology stack detection — builds the ``ProjectProfile``.

The profile drives scanner selection: there is no point running a Go vulnerability
scan on a pure Python repository, and running every scanner everywhere is how a
security tool earns a reputation for being slow.

Detection is filesystem-only and deliberately cheap. It reads file names, and peeks
at the first few kilobytes of YAML to tell a Kubernetes manifest from a CI config.
It never executes anything from the target tree (INV-5) and never resolves a
dependency graph — that is a scanner's job, inside a sandbox.

Every list on the emitted profile is sorted, so the same tree yields a
byte-identical profile no matter what order the filesystem hands back entries
(INV-3).
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Final

import structlog

from cyberops_kit.core.errors import DetectionError
from cyberops_kit.core.models import (
    CIPlatform,
    IaCKind,
    LanguageStat,
    PackageManager,
    ProjectProfile,
)

logger = structlog.get_logger(__name__)

MAX_FILES: Final = 200_000
"""Walk ceiling. A tree larger than this is pathological; stop and report."""

YAML_PEEK_BYTES: Final = 2048
"""Enough to see ``apiVersion:`` and ``kind:`` without reading whole manifests."""

PRUNED_DIRS: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".nox",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "node_modules",
        "bower_components",
        "vendor",
        "dist",
        "build",
        "target",
        ".next",
        ".nuxt",
        ".gradle",
        ".idea",
        ".vscode",
        "site-packages",
        ".terraform",
    }
)
"""Directories excluded from detection. Vendored trees skew language statistics."""

LANGUAGE_BY_EXTENSION: Final[dict[str, str]] = {
    ".py": "Python",
    ".pyi": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".scala": "Scala",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".fs": "F#",
    ".c": "C",
    ".h": "C",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".m": "Objective-C",
    ".swift": "Swift",
    ".sh": "Shell",
    ".bash": "Shell",
    ".zsh": "Shell",
    ".ps1": "PowerShell",
    ".pl": "Perl",
    ".lua": "Lua",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".erl": "Erlang",
    ".hs": "Haskell",
    ".dart": "Dart",
    ".sql": "SQL",
    ".tf": "HCL",
    ".hcl": "HCL",
}

MANIFEST_BY_FILENAME: Final[dict[str, PackageManager]] = {
    "package.json": PackageManager.NPM,
    "requirements.txt": PackageManager.PIP,
    "setup.py": PackageManager.PIP,
    "setup.cfg": PackageManager.PIP,
    "pyproject.toml": PackageManager.PIP,
    "pipfile": PackageManager.PIP,
    "go.mod": PackageManager.GO_MODULES,
    "cargo.toml": PackageManager.CARGO,
    "pom.xml": PackageManager.MAVEN,
    "build.gradle": PackageManager.GRADLE,
    "build.gradle.kts": PackageManager.GRADLE,
    "gemfile": PackageManager.BUNDLER,
    "composer.json": PackageManager.COMPOSER,
}

LOCKFILE_BY_FILENAME: Final[dict[str, PackageManager]] = {
    "package-lock.json": PackageManager.NPM,
    "npm-shrinkwrap.json": PackageManager.NPM,
    "yarn.lock": PackageManager.YARN,
    "pnpm-lock.yaml": PackageManager.PNPM,
    "poetry.lock": PackageManager.POETRY,
    "uv.lock": PackageManager.UV,
    "pipfile.lock": PackageManager.PIP,
    "go.sum": PackageManager.GO_MODULES,
    "cargo.lock": PackageManager.CARGO,
    "gemfile.lock": PackageManager.BUNDLER,
    "composer.lock": PackageManager.COMPOSER,
    "packages.lock.json": PackageManager.NUGET,
}

CONTAINER_FILENAMES: Final[frozenset[str]] = frozenset(
    {"dockerfile", "containerfile", ".dockerignore"}
)

COMPOSE_FILENAMES: Final[frozenset[str]] = frozenset(
    {
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    }
)

CI_BY_PATH: Final[tuple[tuple[str, CIPlatform], ...]] = (
    (".github/workflows", CIPlatform.GITHUB_ACTIONS),
    (".gitlab-ci.yml", CIPlatform.GITLAB_CI),
    (".circleci/config.yml", CIPlatform.CIRCLECI),
    ("jenkinsfile", CIPlatform.JENKINS),
    ("azure-pipelines.yml", CIPlatform.AZURE_PIPELINES),
    (".travis.yml", CIPlatform.TRAVIS),
)

APPLICATION_MARKERS: Final[frozenset[str]] = frozenset(
    {"dockerfile", "containerfile", "procfile", "main.go", "manage.py", "app.py"}
)


class ProjectDetector:
    """Walks a tree once and derives a :class:`ProjectProfile` from what it sees."""

    def __init__(self, root: Path, *, exclude_paths: tuple[str, ...] = ()) -> None:
        """Initialize the detector.

        Args:
            root: Repository root to inspect.
            exclude_paths: Additional directory names to prune, from config.
        """
        self.root = root
        self._pruned = PRUNED_DIRS | {p.strip("/*") for p in exclude_paths if p}

    def detect(self) -> ProjectProfile:
        """Build the project profile.

        Returns:
            A fully-populated, deterministically-ordered profile.

        Raises:
            DetectionError: The root is not a readable directory, or the tree
                exceeds :data:`MAX_FILES`.
        """
        if not self.root.is_dir():
            raise DetectionError(f"target is not a directory: {self.root}")

        languages: Counter[str] = Counter()
        package_managers: set[PackageManager] = set()
        manifests: set[str] = set()
        lockfiles: set[str] = set()
        container_files: set[str] = set()
        iac: set[IaCKind] = set()
        ci_workflows: set[str] = set()
        ci_platform: CIPlatform | None = None
        application_markers = 0
        file_count = 0
        total_bytes = 0

        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in self._pruned)
            current = Path(dirpath)

            for filename in sorted(filenames):
                file_count += 1
                if file_count > MAX_FILES:
                    raise DetectionError(
                        f"tree exceeds {MAX_FILES} files; refusing to scan",
                        remediation="Narrow the target, or add scanners.exclude_paths.",
                    )

                path = current / filename
                relative = self._relative(path)
                lowered = filename.lower()
                total_bytes += self._size(path)

                language = LANGUAGE_BY_EXTENSION.get(path.suffix.lower())
                if language:
                    languages[language] += 1

                if manager := MANIFEST_BY_FILENAME.get(lowered):
                    package_managers.add(manager)
                    manifests.add(relative)

                if manager := LOCKFILE_BY_FILENAME.get(lowered):
                    package_managers.add(manager)
                    lockfiles.add(relative)

                if lowered in CONTAINER_FILENAMES or lowered.startswith("dockerfile."):
                    container_files.add(relative)

                if lowered in COMPOSE_FILENAMES:
                    iac.add(IaCKind.DOCKER_COMPOSE)
                    container_files.add(relative)

                if lowered in APPLICATION_MARKERS:
                    application_markers += 1

                detected_iac = self._detect_iac(path, relative, lowered)
                iac.update(detected_iac)

                platform, workflow = self._detect_ci(relative, lowered)
                # First match in CI_BY_PATH order wins, so a repo with both
                # Actions and a legacy .travis.yml reports the primary platform.
                if platform is not None and (
                    ci_platform is None or _ci_rank(platform) < _ci_rank(ci_platform)
                ):
                    ci_platform = platform
                if workflow:
                    ci_workflows.add(relative)

        profile = ProjectProfile(
            languages=[
                LanguageStat(name=name, file_count=count)
                # Descending count, then name, so ties never depend on walk order.
                for name, count in sorted(languages.items(), key=lambda kv: (-kv[1], kv[0]))
            ],
            package_managers=sorted(package_managers, key=lambda m: m.value),
            manifests=sorted(manifests),
            lockfiles=sorted(lockfiles),
            containerized=bool(container_files),
            container_files=sorted(container_files),
            iac=sorted(iac, key=lambda k: k.value),
            ci_platform=ci_platform,
            ci_workflows=sorted(ci_workflows),
            distribution=self._classify(package_managers, application_markers),
            file_count=file_count,
            total_bytes=total_bytes,
        )

        logger.debug(
            "detect.complete",
            languages=profile.language_names[:5],
            package_managers=[m.value for m in profile.package_managers],
            file_count=file_count,
        )
        return profile

    def _relative(self, path: Path) -> str:
        """Return a POSIX path relative to the repository root.

        Args:
            path: Absolute path inside the tree.

        Returns:
            Repo-relative POSIX string.
        """
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:  # pragma: no cover - os.walk stays under root
            return path.as_posix()

    @staticmethod
    def _size(path: Path) -> int:
        """Return a file's size, treating unreadable entries as zero.

        Args:
            path: File to stat.

        Returns:
            Size in bytes, or 0 for broken symlinks and permission errors.
        """
        try:
            return path.stat().st_size
        except OSError:
            return 0

    def _detect_iac(self, path: Path, relative: str, lowered: str) -> set[IaCKind]:
        """Identify infrastructure-as-code from a single file.

        Args:
            path: Absolute path to the file.
            relative: Repo-relative POSIX path.
            lowered: Lowercased filename.

        Returns:
            The IaC kinds this file provides evidence for.
        """
        kinds: set[IaCKind] = set()

        if lowered.endswith((".tf", ".tfvars")):
            kinds.add(IaCKind.TERRAFORM)
        if lowered == "chart.yaml":
            kinds.add(IaCKind.HELM)
        if lowered in {"playbook.yml", "playbook.yaml", "site.yml", "site.yaml"}:
            kinds.add(IaCKind.ANSIBLE)
        if relative.startswith(("roles/", "ansible/")) and lowered.endswith((".yml", ".yaml")):
            kinds.add(IaCKind.ANSIBLE)

        if lowered.endswith((".yml", ".yaml", ".json", ".template")):
            head = self._peek(path)
            if head:
                if "apiversion:" in head and "kind:" in head:
                    kinds.add(IaCKind.KUBERNETES)
                if "awstemplateformatversion" in head:
                    kinds.add(IaCKind.CLOUDFORMATION)

        return kinds

    @staticmethod
    def _peek(path: Path) -> str:
        """Read the first bytes of a file, lowercased, for structural sniffing.

        Args:
            path: File to sample.

        Returns:
            Lowercased head of the file, or an empty string if unreadable.
        """
        try:
            with path.open("rb") as handle:
                return handle.read(YAML_PEEK_BYTES).decode("utf-8", errors="ignore").lower()
        except OSError:
            return ""

    @staticmethod
    def _detect_ci(relative: str, lowered: str) -> tuple[CIPlatform | None, bool]:
        """Identify the CI platform from a path.

        Args:
            relative: Repo-relative POSIX path.
            lowered: Lowercased filename.

        Returns:
            The detected platform (or ``None``) and whether the file is a workflow
            definition worth listing.
        """
        normalized = relative.lower()
        for marker, platform in CI_BY_PATH:
            if marker.endswith("/"):  # pragma: no cover - defensive
                marker = marker.rstrip("/")
            if normalized.startswith(f"{marker}/"):
                is_workflow = normalized.endswith((".yml", ".yaml"))
                return platform, is_workflow
            if normalized == marker or lowered == marker:
                return platform, True
        return None, False

    @staticmethod
    def _classify(package_managers: set[PackageManager], application_markers: int) -> str:
        """Classify the project as a library, an application, or unknown.

        Best-effort and conservative: an ambiguous tree stays ``unknown`` rather than
        asserting something the evidence does not support.

        Args:
            package_managers: Detected package managers.
            application_markers: Count of application-shaped marker files.

        Returns:
            One of ``library``, ``application``, or ``unknown``.
        """
        if application_markers:
            return "application"
        if package_managers:
            return "library"
        return "unknown"


def _ci_rank(platform: CIPlatform) -> int:
    """Return the precedence of a CI platform for primary-platform selection.

    Args:
        platform: A detected platform.

    Returns:
        Lower is higher precedence, following ``CI_BY_PATH`` order.
    """
    order = [entry[1] for entry in CI_BY_PATH]
    return order.index(platform)


def detect_project(root: Path, *, exclude_paths: tuple[str, ...] = ()) -> ProjectProfile:
    """Build a :class:`ProjectProfile` for a tree.

    Args:
        root: Repository root to inspect.
        exclude_paths: Additional directory names to prune.

    Returns:
        The detected profile.

    Raises:
        DetectionError: The root is unreadable or the tree is too large.
    """
    return ProjectDetector(root, exclude_paths=exclude_paths).detect()
