const _ = require("lodash");

// Conta os itens de uma lista por tipo.
function resumo(itens) {
  return _.countBy(itens, "tipo");
}

module.exports = { resumo };

if (require.main === module) {
  console.log(resumo([{ tipo: "imagem" }, { tipo: "pacote" }, { tipo: "imagem" }]));
}
