from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = shutil.which("powershell")
WINDOWS_ROOT = Path(os.environ.get("WINDIR", r"C:\Windows"))
CSC_CANDIDATES = (
    WINDOWS_ROOT / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "csc.exe",
    WINDOWS_ROOT / "Microsoft.NET" / "Framework" / "v4.0.30319" / "csc.exe",
)
CSC = next((candidate for candidate in CSC_CANDIDATES if candidate.is_file()), None)


@unittest.skipUnless(
    POWERSHELL and CSC,
    "Windows PowerShell and the .NET C# compiler are required for Authenticode verification",
)
class ReleaseVerificationTests(unittest.TestCase):
    def run_script(self, script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(POWERSHELL),
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(ROOT / "scripts" / script),
                *arguments,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def create_fixture(self, release_dir: Path) -> tuple[Path, str]:
        tag = "v9.9.9"
        commit = "a" * 40
        setup = release_dir / "RMM-Hunter-Setup-9.9.9-x64.exe"
        portable = release_dir / "RMM-Hunter-Portable-9.9.9-x64.exe"
        blockmap = release_dir / f"{setup.name}.blockmap"
        source = release_dir / "fixture.cs"
        source.write_text(
            "public static class Fixture { public static int Main() { return 0; } }\n",
            encoding="utf-8",
        )
        compiled = subprocess.run(
            [str(CSC), "/nologo", "/target:exe", f"/out:{setup}", str(source)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
        shutil.copyfile(setup, portable)
        blockmap.write_bytes(b"fixture blockmap\n")

        setup_sha512 = base64.b64encode(hashlib.sha512(setup.read_bytes()).digest()).decode("ascii")
        (release_dir / "latest.yml").write_text(
            "\n".join(
                [
                    "version: 9.9.9",
                    "files:",
                    f"  - url: {setup.name}",
                    f"    sha512: {setup_sha512}",
                    f"    size: {setup.stat().st_size}",
                    f"path: {setup.name}",
                    f"sha512: {setup_sha512}",
                    "releaseDate: '2026-07-13T00:00:00.000Z'",
                    "",
                ]
            ),
            encoding="utf-8",
        )

        generated = self.run_script(
            "generate-release-manifest.ps1",
            "-ReleaseDir",
            str(release_dir),
            "-SourceRef",
            tag,
            "-SourceSha",
            commit,
            "-Repository",
            "MDP-Studio/rmm-hunter",
            "-RunId",
            "123",
            "-RunUrl",
            "https://github.example/actions/runs/123",
            "-SigningMode",
            "unsigned-beta",
        )
        self.assertEqual(generated.returncode, 0, generated.stdout + generated.stderr)

        names = [
            "rmm-hunter-release-manifest.json",
            "SHA256SUMS.txt",
            "VERIFY_RELEASE.md",
            setup.name,
            portable.name,
            blockmap.name,
            "latest.yml",
        ]
        assets = []
        for name in names:
            path = release_dir / name
            assets.append(
                {
                    "name": name,
                    "size": path.stat().st_size,
                    "digest": f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}",
                    "browser_download_url": f"https://github.example/{name}",
                }
            )
        metadata = {
            "tag_name": tag,
            "draft": False,
            "html_url": "https://github.example/releases/v9.9.9",
            "assets": assets,
        }
        metadata_path = release_dir / "release-metadata.json"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        return metadata_path, commit

    def test_unsigned_published_release_ceremony_and_tamper_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release_dir = Path(tmp)
            metadata_path, commit = self.create_fixture(release_dir)
            report_path = release_dir / "verification-result.json"

            verified = self.run_script(
                "verify-published-release.ps1",
                "-Tag",
                "v9.9.9",
                "-ReleaseDir",
                str(release_dir),
                "-ReleaseMetadataPath",
                str(metadata_path),
                "-TagCommit",
                commit,
                "-ReportPath",
                str(report_path),
            )
            self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
            report = json.loads(report_path.read_text(encoding="utf-8-sig"))
            self.assertEqual(report["signing"]["mode"], "unsigned-beta")
            self.assertEqual(report["checks"]["authenticode_policy"], "verified")

            (release_dir / "RMM-Hunter-Portable-9.9.9-x64.exe").write_bytes(b"tampered")
            rejected = self.run_script(
                "verify-published-release.ps1",
                "-Tag",
                "v9.9.9",
                "-ReleaseDir",
                str(release_dir),
                "-ReleaseMetadataPath",
                str(metadata_path),
                "-TagCommit",
                commit,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("size mismatch", rejected.stdout + rejected.stderr)

    def test_signed_manifest_requires_pinned_publisher_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            release_dir = Path(tmp)
            self.create_fixture(release_dir)

            rejected = self.run_script(
                "generate-release-manifest.ps1",
                "-ReleaseDir",
                str(release_dir),
                "-SourceRef",
                "v9.9.9",
                "-SourceSha",
                "a" * 40,
                "-Repository",
                "MDP-Studio/rmm-hunter",
                "-SigningMode",
                "signpath",
            )

            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("expected publisher subject", (rejected.stdout + rejected.stderr).lower())


if __name__ == "__main__":
    unittest.main()
