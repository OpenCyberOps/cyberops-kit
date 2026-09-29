# CyberOps Kit — Nix package.
#
# Written in nixpkgs style (callPackage-able, no flake-specific inputs) so it can be
# submitted upstream with minimal changes.
#
# The `cyberops` wrapper prepends every external scanner to PATH. Scanners are
# resolved with `shutil.which` at run time, so this is the only integration needed:
# no Python code knows or cares that it is running from the Nix store. The scanner
# versions are pinned by flake.lock, which is what makes a Nix-installed CyberOps Kit
# reproducible end to end (INV-3): same commit, same lock, same tool versions.
{
  lib,
  stdenv,
  python3Packages,
  versionCheckHook,
  git,
  scorecard,
  osv-scanner,
  gitleaks,
  syft,
  trivy,
  semgrep,
  slsa-verifier,
  # Bundle the external scanners on the wrapper's PATH. Disable for a
  # pip-equivalent install that uses whatever scanners the host already has.
  withScanners ? true,
  # Phase 2 advisory providers (the `ai` extra). Off by default, mirroring pip: the
  # deterministic core never carries supply chain surface for an opt-in feature.
  withAI ? false,
}:

let
  pyproject = lib.importTOML ../pyproject.toml;

  # git is required by ingest regardless of which scanners run.
  scanners = lib.filter (lib.meta.availableOn stdenv.hostPlatform) [
    scorecard
    osv-scanner
    gitleaks
    syft
    trivy
    semgrep
    slsa-verifier
  ];
  runtimePath = [ git ] ++ lib.optionals withScanners scanners;
in
python3Packages.buildPythonApplication {
  pname = "cyberops-kit";
  inherit (pyproject.project) version;
  pyproject = true;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../pyproject.toml
      ../README.md
      ../LICENSE
      ../src
      ../tests
    ];
  };

  build-system = [ python3Packages.hatchling ];

  dependencies =
    with python3Packages;
    [
      typer
      pydantic
      structlog
      jinja2
      pyyaml
    ]
    ++ lib.optionals withAI [
      anthropic
      openai
    ];

  # Prefix, not suffix: the pinned scanners win over anything else on the user's
  # PATH, so the tool versions recorded in run_metadata are the locked ones.
  # Container runtimes (docker/podman) are deliberately not bundled; they come from
  # the system, where the daemon and its privileges are configured.
  makeWrapperArgs = [
    "--prefix"
    "PATH"
    ":"
    (lib.makeBinPath runtimePath)
  ];

  nativeCheckInputs = [
    python3Packages.pytestCheckHook
    python3Packages.pytest-asyncio
    git
    versionCheckHook
  ];

  # Unit tests and the INV-* invariant guards gate every Nix build. Integration
  # tests need Docker and network access, neither of which the build sandbox has.
  enabledTestPaths = [
    "tests/unit"
    "tests/invariants"
  ];

  preCheck = ''
    export HOME="$TMPDIR"
  '';

  versionCheckProgramArg = "version";

  pythonImportsCheck = [ "cyberops_kit" ];

  passthru = {
    inherit scanners;
  };

  meta = {
    description = "Reproducible, auditable security report cards for any software project";
    longDescription = ''
      CyberOps Kit analyzes a software project, orchestrates the OpenSSF tool
      ecosystem (Scorecard, OSV-Scanner, Semgrep, Gitleaks, Trivy, Syft), evaluates
      supply chain posture against SLSA, generates SBOMs, and produces a
      deterministic security report card. It augments professional security
      review; it does not replace it.
    '';
    homepage = pyproject.project.urls.Homepage;
    changelog = pyproject.project.urls.Changelog;
    license = lib.licenses.asl20;
    mainProgram = "cyberops";
    platforms = lib.platforms.unix;
  };
}
