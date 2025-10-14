#!/usr/bin/env bash
# bootstrap_wstunnel.sh — 引导下载并以 base64 在内存中执行真实安装脚本（非明文）
set -euo pipefail

# ---- 配置区 ----
RAW_URL="https://raw.githubusercontent.com/zszgm8/ws/main/install_wstunnel.sh"
TMP_DIR="$(mktemp -d /tmp/wstunnel_bootstrap.XXXXXX)"
RAW_FILE="${TMP_DIR}/install.raw.sh"
B64_FILE="${TMP_DIR}/install.b64"
# -----------------

cleanup() {
  rm -rf "${TMP_DIR}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[*] 从远端拉取脚本（临时）..."
if ! command -v curl >/dev/null 2>&1; then
  echo "[*] 未检测到 curl，尝试使用 wget..."
  if command -v wget >/dev/null 2>&1; then
    wget -q -O "${RAW_FILE}" "${RAW_URL}" || { echo "[ERROR] wget 下载失败"; exit 1; }
  else
    echo "[ERROR] 系统缺少 curl 和 wget，请先安装一个"; exit 1
  fi
else
  curl -fsSL "${RAW_URL}" -o "${RAW_FILE}" || { echo "[ERROR] curl 下载失败"; exit 1; }
fi

# 确保换行为 LF（移除可能的 CR）
tr -d '\r' < "${RAW_FILE}" > "${RAW_FILE}.lf" && mv "${RAW_FILE}.lf" "${RAW_FILE}"

# 将原始脚本编码为单行 base64（避免换行导致的问题）
if base64 --help 2>&1 | grep -q -- '-w'; then
  base64 -w0 "${RAW_FILE}" > "${B64_FILE}"
else
  # 某些系统 base64 不支持 -w0
  base64 "${RAW_FILE}" | tr -d '\n' > "${B64_FILE}"
fi

# 安全提示（可选）：显示已编码但不显示原文
echo "[*] 已将远端脚本编码为 base64（仅在内存执行），开始解码并执行..."

# 解码并在内存中执行（不会把明文写入可长期访问的路径）
set +e
base64 -d "${B64_FILE}" | bash -s -- "$@"
rc=$?
set -e

if [ $rc -ne 0 ]; then
  echo "[ERROR] 解码后的安装脚本执行失败（退出码 $rc）"
  echo "[INFO] 你可以查看临时目录（若仍存在）: ${TMP_DIR}"
  exit $rc
fi

echo "[*] 安装脚本执行完毕（临时文件已清理）"
exit 0
