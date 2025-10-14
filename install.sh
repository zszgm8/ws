#!/usr/bin/env bash
# bootstrap_wstunnel.sh — 更鲁棒的引导脚本（Ubuntu/Debian）
set -euo pipefail

RAW_URL="https://raw.githubusercontent.com/zszgm8/ws/main/install_wstunnel.sh"
TMP_DIR="$(mktemp -d /tmp/wstunnel_bootstrap.XXXXXX)"
RAW_FILE="${TMP_DIR}/install.raw.sh"
CLEAN_FILE="${TMP_DIR}/install.clean.sh"
B64_FILE="${TMP_DIR}/install.b64"

cleanup() {
  # 保留临时目录当出错，便于调试；成功则删除
  if [ "${_BOOTSTRAP_OK:-0}" -eq 1 ]; then
    rm -rf "${TMP_DIR}" >/dev/null 2>&1 || true
  else
    echo "[INFO] 临时文件保留以便调试: ${TMP_DIR}"
  fi
}
trap cleanup EXIT

echo "[*] 临时目录: ${TMP_DIR}"
echo "[*] 下载远端脚本: ${RAW_URL}"

# 下载（支持 curl/wget），并显示 HTTP 状态（如果可能）
if command -v curl >/dev/null 2>&1; then
  if ! curl -fsSL -D "${TMP_DIR}/http.headers" -o "${RAW_FILE}" "${RAW_URL}"; then
    echo "[ERROR] curl 下载失败。HTTP headers:"
    sed -n '1,80p' "${TMP_DIR}/http.headers" || true
    echo "[ERROR] 若受限，请确保目标服务器能访问 raw.githubusercontent.com"
    exit 1
  fi
elif command -v wget >/dev/null 2>&1; then
  if ! wget -q -O "${RAW_FILE}" "${RAW_URL}"; then
    echo "[ERROR] wget 下载失败。"
    exit 1
  fi
else
  echo "[ERROR] 系统缺少 curl 或 wget，无法下载远端脚本。"
  exit 1
fi

# 快速检测文件是否看起来是脚本（防止下载到 HTML 错误页面）
echo "[*] 下载内容预览（前 40 行）:"
sed -n '1,40p' "${RAW_FILE}" || true
echo "----- end preview -----"

# 强制移除 CR (\r)，保证 LF 风格
tr -d '\r' < "${RAW_FILE}" > "${CLEAN_FILE}" || { echo "[ERROR] tr 命令失败"; exit 1; }

# 再次检查非空
if [ ! -s "${CLEAN_FILE}" ]; then
  echo "[ERROR] 清理后脚本为空，下载可能失败或被阻断。请检查 ${RAW_URL}"
  exit 1
fi

# 生成单行 base64（兼容不同 base64 实现）
if base64 --help 2>&1 | grep -q -- '-w'; then
  base64 -w0 "${CLEAN_FILE}" > "${B64_FILE}" || { echo "[ERROR] base64 编码失败"; exit 1; }
else
  base64 "${CLEAN_FILE}" | tr -d '\n' > "${B64_FILE}" || { echo "[ERROR] base64 编码失败"; exit 1; }
fi

# 额外验证：B64 文件不应包含空格行或不可打印字符（简单检查）
if ! head -c 4 "${B64_FILE}" >/dev/null 2>&1; then
  echo "[ERROR] base64 文件创建失败或为空"
  exit 1
fi

echo "[*] 已将远端脚本编码为 base64（仅在内存执行）。准备解码并执行..."

# 选择可用的解码方式并执行
_exec_b64_and_run() {
  local dec_cmd="$1"
  if ! ${dec_cmd} "${B64_FILE}" 2> "${TMP_DIR}/b64_decode.err" | bash -s -- "$@"; then
    return 1
  fi
  return 0
}

# 试三种常见解码方式
if command -v base64 >/dev/null 2>&1; then
  # 先尝试 POSIX GNU base64 -d
  if base64 --help 2>&1 | grep -q -- '-d'; then
    echo "[*] 使用 'base64 -d' 解码..."
    if base64 -d "${B64_FILE}" | bash -s -- "$@"; then
      _BOOTSTRAP_OK=1
      echo "[*] 安装脚本执行成功（使用 base64 -d）"
      exit 0
    fi
  fi
  # 尝试 --decode
  if base64 --help 2>&1 | grep -q -- '--decode'; then
    echo "[*] 使用 'base64 --decode' 解码..."
    if base64 --decode "${B64_FILE}" | bash -s -- "$@"; then
      _BOOTSTRAP_OK=1
      echo "[*] 安装脚本执行成功（使用 base64 --decode）"
      exit 0
    fi
  fi
fi

# 最后尝试 openssl（许多系统都安装了）
if command -v openssl >/dev/null 2>&1; then
  echo "[*] 使用 'openssl base64 -d' 解码..."
  if openssl base64 -d -in "${B64_FILE}" 2> "${TMP_DIR}/openssl.err" | bash -s -- "$@"; then
    _BOOTSTRAP_OK=1
    echo "[*] 安装脚本执行成功（使用 openssl base64 -d）"
    exit 0
  fi
fi

# 若都失败，打印诊断信息并退出
echo "[ERROR] 所有 base64 解码尝试均失败。请查看下列调试信息："
echo "----- ${RAW_FILE} (前 60 行) -----"
sed -n '1,60p' "${RAW_FILE}" || true
echo "----- ${CLEAN_FILE} (前 60 行) -----"
sed -n '1,60p' "${CLEAN_FILE}" || true
echo "----- ${B64_FILE} (前 200 字符) -----"
head -c 200 "${B64_FILE}" | sed -n '1,5p' || true
echo "----- ${TMP_DIR}/b64_decode.err -----"
sed -n '1,200p' "${TMP_DIR}/b64_decode.err" || true
echo "----- ${TMP_DIR}/openssl.err -----"
sed -n '1,200p' "${TMP_DIR}/openssl.err" || true

echo "[INFO] 若你愿意，把上面内容贴给我（尤其是 CLEAN_FILE 的前 60 行和 b64_decode.err），我来帮你分析。"
exit 127
