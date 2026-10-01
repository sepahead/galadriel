"""Source-policy controls; synthetic metadata never claims an executed Cargo graph."""

import copy
from pathlib import Path
import tempfile
import tomllib
import unittest

import verify_source as verifier

COMPONENT = Path(__file__).resolve().parent
ROOT = COMPONENT.parents[1]


def fixture():
    profile = verifier.document(COMPONENT / "source-profile.json")
    load = lambda p: tomllib.loads(verifier.read(p).decode())
    values = [profile, load(ROOT / "Cargo.toml"), load(COMPONENT / "Cargo.toml"), load(ROOT / "Cargo.lock"), load(COMPONENT / "Cargo.lock"), load(COMPONENT / "deny.toml")]
    # The synthetic positive represents the intended public pin, never sibling authority.
    sdk = profile["sdk"]
    values[2]["dependencies"]["ncp-local"] = {"version": "=1.0.0", "git": sdk["repository"], "rev": sdk["revision"], "optional": True}
    for package in values[4]["package"]:
        if package["name"] == "ncp-local":
            package["source"] = verifier.sdk_source(profile)
    return values


def graph(native):
    profile = fixture()[0]
    names = ["galadriel-local-adapter", "galadriel-core"] + (["ncp-local"] if native else [])
    packages = [{"id": name, "name": name, "version": "1.0.0" if name == "ncp-local" else "0.9.0", "source": verifier.sdk_source(profile) if name == "ncp-local" else None, "manifest_path": str(COMPONENT / "Cargo.toml" if name == "galadriel-local-adapter" else COMPONENT.parent / name / "Cargo.toml")} for name in names]
    nodes = [{"id": name, "features": ["ncp-local"] if native and index == 0 else [], "deps": [{"pkg": dependency} for dependency in names[1:]] if index == 0 else []} for index, name in enumerate(names)]
    return {"packages": packages, "workspace_members": names[:1], "resolve": {"root": names[0], "nodes": nodes}}


class SourcePolicyTests(unittest.TestCase):
    def test_exact_independent_profile_is_admitted(self):
        verifier.check_manifests(*fixture())

    def test_manifest_boundary_changes_reject(self):
        mutations = {
            "sibling": lambda v: v[2]["dependencies"]["ncp-local"].update(path="../../../NCP/local/rust"),
            "floating": lambda v: v[2]["dependencies"]["ncp-local"].pop("rev"),
            "wrong_revision": lambda v: v[2]["dependencies"]["ncp-local"].update(rev="a" * 40),
            "published": lambda v: v[2]["package"].update(publish=True),
            "default_native": lambda v: v[2]["features"].update(default=["ncp-local"]),
            "core_copy": lambda v: v[2]["dependencies"]["galadriel-core"].update(path="copied-core"),
            "root_member": lambda v: v[1]["workspace"]["members"].append("crates/galadriel-local-adapter"),
            "authority": lambda v: v[0].update(release_authority=True),
            "exception": lambda v: v[5]["advisories"]["ignore"].append("unrelated"),
            "unknown_git": lambda v: v[5]["sources"].update({"unknown-git": "allow"}),
            "changed_root_pin": lambda v: v[3]["package"].append({"name": "unexpected", "source": "git+https://example.invalid/repo#" + "a" * 40}),
            "changed_native_pin": lambda v: next(p for p in v[4]["package"] if p["name"] == "ncp-local").update(source="git+https://example.invalid/repo#" + "a" * 40),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                values = copy.deepcopy(fixture())
                mutate(values)
                with self.assertRaises(ValueError):
                    verifier.check_manifests(*values)

    def test_pure_and_native_graphs_are_distinct(self):
        for native in [False, True]:
            self.assertEqual(verifier.check_graph(graph(native), fixture()[0], COMPONENT, native=native), 3 if native else 2)

    def test_missing_native_and_unexpected_native_reject(self):
        for native in [False, True]:
            with self.assertRaises(ValueError):
                verifier.check_graph(graph(native), fixture()[0], COMPONENT, native=not native)

    def test_changed_source_or_version_rejects(self):
        for change in ["source", "registry_substitution", "version", "core_path", "core_registry", "core_version"]:
            with self.subTest(change=change):
                value = graph(True)
                if change == "source":
                    value["packages"][-1]["source"] = "git+https://example.invalid/unlisted"
                elif change == "registry_substitution":
                    value["packages"][-1]["source"] = "registry+https://github.com/rust-lang/crates.io-index"
                elif change == "version":
                    value["packages"][-1]["version"] = "0.8.0"
                elif change == "core_registry":
                    value["packages"][1]["source"] = "registry+https://github.com/rust-lang/crates.io-index"
                elif change == "core_version":
                    value["packages"][1]["version"] = "0.8.0"
                else:
                    value["packages"][1]["manifest_path"] = "/unlisted/Cargo.toml"
                with self.assertRaises(ValueError):
                    verifier.check_graph(value, fixture()[0], COMPONENT, native=True)

    def test_duplicate_graph_identities_reject(self):
        for field in ["packages", "nodes"]:
            with self.subTest(field=field):
                value = graph(True)
                entries = value["packages"] if field == "packages" else value["resolve"]["nodes"]
                entries.append(copy.deepcopy(entries[-1]))
                with self.assertRaises(ValueError):
                    verifier.check_graph(value, fixture()[0], COMPONENT, native=True)

    def test_undeclared_feature_selection_rejects(self):
        for index in range(3):
            with self.subTest(index=index):
                value = graph(True)
                value["resolve"]["nodes"][index]["features"].append("unexpected")
                with self.assertRaises(ValueError):
                    verifier.check_graph(value, fixture()[0], COMPONENT, native=True)

    def test_unrelated_runtime_dependency_rejects(self):
        for name in ["pid-core", "ncp-core", "ncp-zenoh", "tokio", "zenoh"]:
            with self.subTest(name=name):
                value = graph(True)
                value["packages"].append({"id": name, "name": name, "source": "registry+https://github.com/rust-lang/crates.io-index"})
                value["resolve"]["nodes"].append({"id": name, "deps": []})
                value["resolve"]["nodes"][0]["deps"].append({"pkg": name})
                with self.assertRaises(ValueError):
                    verifier.check_graph(value, fixture()[0], COMPONENT, native=True)

    def test_duplicate_json_and_symlink_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data.json"
            path.write_text('{"a":1,"a":2}')
            with self.assertRaises(ValueError):
                verifier.document(path)
            path.write_text('{"a":1}')
            self.assertEqual(verifier.document(path), {"a": 1})
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                verifier.document(link)


if __name__ == "__main__":
    unittest.main()
