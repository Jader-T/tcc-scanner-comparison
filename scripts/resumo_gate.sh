#!/usr/bin/env bash
# Gera o resumo em Markdown do relatório JSON do Trivy.
# Uso: resumo_gate.sh trivy.json imagem > resumo.md
set -euo pipefail
RELATORIO="$1"
IMAGEM="$2"

BLOQUEANTES=$(jq '[.Results[]?.Vulnerabilities[]?
  | select((.Severity == "CRITICAL" or .Severity == "HIGH") and ((.FixedVersion // "") != ""))] | length' "$RELATORIO")

echo "<!-- security-gate -->"
if [ "$BLOQUEANTES" -gt 0 ]; then
  echo "## Workflow reprovado"
  echo
  echo "A imagem \`$IMAGEM\` tem **$BLOQUEANTES** vulnerabilidade(s) crítica(s) ou alta(s) **com correção disponível**."
else
  echo "## Workflow aprovado"
  echo
  echo "A imagem \`$IMAGEM\` não tem vulnerabilidades críticas ou altas com correção disponível."
fi
echo
echo "**Política:** bloqueia vulnerabilidades de severidade crítica ou alta que já tenham versão corrigida. As demais são apenas informadas."
echo
echo "| Severidade | Total | Com correção |"
echo "|---|---:|---:|"
jq -r '[.Results[]?.Vulnerabilities[]?] as $v
  | ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"][] as $s
  | "| \($s) | \([$v[] | select(.Severity == $s)] | length) | \([$v[] | select(.Severity == $s and ((.FixedVersion // "") != ""))] | length) |"' "$RELATORIO"

if [ "$BLOQUEANTES" -gt 0 ]; then
  echo
  echo "### Vulnerabilidades que bloqueiam o merge"
  echo
  echo "| ID | Severidade | Pacote | Versão instalada | Versão corrigida |"
  echo "|---|---|---|---|---|"
  jq -r '[.Results[]?.Vulnerabilities[]?
      | select((.Severity == "CRITICAL" or .Severity == "HIGH") and ((.FixedVersion // "") != ""))]
    | unique_by(.VulnerabilityID + .PkgName) | .[:20][]
    | "| \(.VulnerabilityID) | \(.Severity) | \(.PkgName) | \(.InstalledVersion) | \(.FixedVersion) |"' "$RELATORIO"
  echo
  echo "Atualize as dependências para as versões corrigidas e envie um novo commit."
fi
