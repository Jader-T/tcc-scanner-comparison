const test = require("node:test");
const assert = require("node:assert");
const { resumo } = require("../index");

test("conta os itens por tipo", () => {
  const itens = [{ tipo: "a" }, { tipo: "a" }, { tipo: "b" }];
  assert.deepStrictEqual(resumo(itens), { a: 2, b: 1 });
});
