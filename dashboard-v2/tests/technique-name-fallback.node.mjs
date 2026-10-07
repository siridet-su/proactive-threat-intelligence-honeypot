import assert from "node:assert/strict";
import test from "node:test";

import { model1TechniqueNameFallback } from "../src/lib/attack-technique-names.ts";

const frozenModel1Labels = [
  "T1003", "T1005", "T1007", "T1011", "T1016", "T1018", "T1021", "T1033",
  "T1040", "T1046", "T1049", "T1053", "T1057", "T1059", "T1068", "T1069",
  "T1070", "T1078", "T1082", "T1083", "T1098", "T1105", "T1110", "T1114",
  "T1125", "T1136", "T1222", "T1518", "T1548", "T1550", "T1552", "T1556",
  "T1560", "T1567", "T1569", "T1570", "T1572", "T1654",
];

test("provides display names for all frozen Model1 labels and not unknown IDs", () => {
  assert.equal(frozenModel1Labels.length, 38);
  for (const id of frozenModel1Labels) {
    assert.ok(model1TechniqueNameFallback(id), `missing bundled name for ${id}`);
  }
  assert.equal(model1TechniqueNameFallback("t1005"), "Data from Local System");
  assert.equal(model1TechniqueNameFallback("T9999"), undefined);
  assert.equal(model1TechniqueNameFallback("T1005.001"), undefined);
});
