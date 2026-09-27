import ast
import pathlib
import unittest


RUNTIME = (
    pathlib.Path(__file__).resolve().parents[1]
    / "evaluation"
    / "model2_v7_32_feature_generation_20260913_v1"
    / "production_runtime_v1"
    / "v7_capstone_runtime.py"
)


class V7SanitizerRegressionTests(unittest.TestCase):
    def test_runtime_has_one_non_recursive_sanitizer_wrapper(self):
        source = RUNTIME.read_text(encoding="utf-8")
        tree = ast.parse(source)

        wrappers = [
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "sanitized_v7_event"
        ]
        self.assertEqual(len(wrappers), 1)
        self.assertEqual(source.count("_v6_base_sanitized_event = v6.sanitized_event"), 1)
        self.assertNotIn("_v6_sanitized_event = v6.sanitized_event", source)

        wrapper_calls = [
            node
            for node in ast.walk(wrappers[0])
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_v6_base_sanitized_event"
        ]
        self.assertEqual(len(wrapper_calls), 1)

    def test_runtime_preserves_only_bounded_projection_fields(self):
        source = RUNTIME.read_text(encoding="utf-8")
        self.assertIn('allowed = {"family", "transfer"}', source)
        self.assertIn('if len(encoded) > 4096:', source)
        self.assertIn('re.fullmatch(r"[0-9a-f]{64}", digest)', source)
        self.assertIn('event["eventid"] == "cowrie.session.file_download"', source)


if __name__ == "__main__":
    unittest.main()
