# 🚀 ChunWebScan - 自動化網頁漏洞掃描工具 🔍

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://example.com) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

> **"工欲善其事，必先利其器。"**  -- 《論語·衛靈公》

## 🌟 項目簡介

ChunWebScan 是一款輕量級、自動化的網頁漏洞掃描工具，專為安全研究人員、開發人員和網站管理員設計。它可以幫助你快速發現網站中潛在的漏洞，例如：

*   **SQL 注入 (SQLi)**：像一位老練的偵探🕵️‍♀️，ChunWebScan 會嘗試各種狡猾的 SQL 注入技巧，找出網站數據庫的秘密入口。
*   **路徑遍歷**：ChunWebScan 會像尋寶獵人一樣🗺️，在網站目錄中穿梭，尋找那些不應該被公開訪問的文件和目錄。
*   **命令注入**：ChunWebScan 會小心翼翼地嘗試向網站發送一些“特殊指令”💻，看看網站是否會乖乖聽話，執行這些指令。
*   **隱藏目錄和文件**：ChunWebScan 會像一位細心的考古學家🏺，挖掘網站中那些被遺忘的角落，找出可能包含敏感信息的隱藏目錄和文件。
*   **Web 應用程式技術檢測**：ChunWebScan 可以像一位博學的學者🎓，識別網站使用的各種技術（例如，Web 服務器、編程語言、框架等）。

ChunWebScan 的目標是成為你手中的一把瑞士軍刀🇨🇭，幫助你快速評估網站的安全性，及早發現並修復漏洞，避免潛在的安全風險。

## ✨ 特性

*   **自動化掃描：**  只需提供目標 URL，ChunWebScan 即可自動執行一系列掃描任務。
*   **多種掃描工具集成：**  ChunWebScan 集成了多種流行的開源掃描工具，包括：
    *   **Dirb/Gobuster:** 用於發現隱藏的目錄和文件。
    *   **Nikto:** 用於掃描已知的 Web 服務器漏洞。
    *   **SQLMap (可選):**  用於檢測和利用 SQL 注入漏洞 (如果已安裝)。
    *   **WhatWeb:**  用於檢測 Web 應用程式使用的技術。
    *   **自定義的 SQL 注入檢測：**  即使沒有安裝 SQLmap，ChunWebScan 也會使用基於 `curl` 的方法來檢測 SQL 注入漏洞。
*   **詳細的報告：**  ChunWebScan 會生成易於閱讀的文本報告和 HTML 報告，詳細列出發現的漏洞和潛在風險。
*   **可定制性：**  你可以通過命令行參數調整掃描的各個方面，例如：
    *   掃描深度
    *   使用的字典檔
    *   執行緒數量
    *   是否啟用/禁用特定類型的掃描
*   **模塊化設計：**  ChunWebScan 的代碼結構清晰，易於擴展和修改。
*   **交互式確認：** 在執行每個主要掃描工具之前, 可以選擇是否執行 (y/n).
*  **響應長度分析:** 通過檢測響應長度的變化, 提高找出SQL注入的效率, 減少誤報.

## 🛠️ 安裝與使用

### 前提條件

*   **Linux 系統** (建議使用 Kali Linux 或其他安全測試發行版)
*   **root 權限**
*   已安裝以下工具：
    *   `curl`
    *   `dirb` 或 `gobuster` (至少安裝其中一個)
    *   `nikto`
    *   `whatweb`
    *   `sqlmap` (可選，但強烈建議安裝)

你可以使用以下命令安裝這些工具（以 Debian/Ubuntu 為例）：

```bash
sudo apt-get update
sudo apt-get install curl dirb gobuster nikto whatweb sqlmap
```

### 獲取代碼

```bash
git clone github.com/chunnnn10/Chunwebscan.git  
cd 你的仓库名
```

### 運行 ChunWebScan

1.  **賦予執行權限：**

    ```bash
    chmod +x chunwebscan.sh  # 注意文件名也改了
    ```

2.  **運行掃描：**

    ```bash
    sudo ./chunwebscan.sh -u <目標URL> [選項] 
    ```

    **範例：**

    ```bash
    # 基本掃描
    sudo ./chunwebscan.sh -u "http://example.com"

    # 指定輸出目錄和字典檔
    sudo ./chunwebscan.sh -u "http://example.com" -o /tmp/scan_results -w /usr/share/wordlists/dirb/big.txt

    # 使用 gobuster 進行目錄掃描，並指定文件擴展名
    sudo ./chunwebscan.sh -u "http://example.com" -T gobuster -e php,html,txt

    # 禁用備用 SQL 注入檢測
    sudo ./chunwebscan.sh -u "http://example.com" -D

    # 執行完整的 Nikto 掃描
    sudo ./chunwebscan.sh -u "http://example.com" -n

    # 顯示幫助信息
    sudo ./chunwebscan.sh -h
    ```

## ⚙️ 選項

| 選項                    | 描述                                                                                                                                                                                                                                                                                         | 預設值                                                                |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `-u, --url <URL>`        | **(必填)** 要掃描的目標 URL。                                                                                                                                                                                                                                                           | 無                                                                    |
| `-o, --output <DIR>`     | 輸出目錄，用於保存掃描結果。                                                                                                                                                                                                                                                                 | `./scan_results`                                                      |
| `-w, --wordlist <FILE>`  | 用於目錄暴力破解的字典檔。                                                                                                                                                                                                                                                               | `/usr/share/dirb/wordlists/common.txt`                                |
| `-t, --threads <NUM>`   | 執行緒數量 (僅適用於支持多線程的工具，如 gobuster)。                                                                                                                                                                                                                                           | `10`                                                                   |
| `-d, --depth <NUM>`     | 目錄爬行深度 (僅適用於支持爬行的工具，如 sqlmap)。                                                                                                                                                                                                                                         | `3`                                                                    |
| `-T, --tool <NAME>`     | 指定目錄掃描工具 ( `dirb` 或 `gobuster` )。                                                                                                                                                                                                                                                 | 自動選擇 (如果兩個都安裝了，優先使用 `gobuster`)                         |
| `-e, --extensions <EXT>` | 僅適用於 `gobuster`，指定要搜索的文件擴展名 (例如：`php,html,txt`)。                                                                                                                                                                                                                            | 無                                                                    |
| `-s, --sql-level <NUM>`  | 僅適用於 `sqlmap`，設置注入級別 (1-5，數字越大，檢測越徹底，但耗時越長)。                                                                                                                                                                                                                         | `1`                                                                    |
| `-n, --nikto-full`      | 執行完整的 Nikto 掃描 (默認為快速掃描)。                                                                                                                                                                                                                                                     | `false` (快速掃描)                                                     |
| `-D, --disable-alt-sql` | 禁用備用 SQL 注入檢測方法 (如果已安裝 `sqlmap`，則默認同時使用 `sqlmap` 和備用方法)。                                                                                                                                                                                                             | `false` (啟用備用 SQL 注入檢測)                                         |
| `-P, --disable-path-traversal` | 禁用路徑遍歷漏洞檢測。                                                                                                                                                  |`false`                                                                 |
|`-C, --disable-cmd-injection`| 禁用命令注入漏洞檢測                                                                                                                                                    | `false`                                                                    |
| `-h, --help`           | 顯示幫助信息。                                                                                                                                                                                                                                                                               | 無                                                                    |

## ⚠️ 免責聲明

*   **ChunWebScan 僅用於教育和研究目的。**
*   **在使用 ChunWebScan 掃描任何網站之前，請務必獲得網站所有者的明確授權。**
*   **未經授權的掃描是非法的，可能會導致法律後果。**
*   **ChunWebScan 的開發者不對任何濫用 ChunWebScan 的行為負責。**
*   掃描結果可能存在誤報或漏報。建議結合人工審查以確認漏洞的真實性和影響。

## 🤝 貢獻

歡迎提交 Pull Request 或 Issue 來幫助改進 ChunWebScan！

## 📝 許可

本项目采用 [MIT 许可证](https://opensource.org/licenses/MIT)。

## 📧 联系

如果你有任何问题或建议，请通过以下方式联系我：

*   GitHub Issues: [[你的仓库地址/issues](https://github.com/chunnnn10)]
*   Email: [chun@chunnnn10.com]

---

**希望 ChunWebScan 能成為你安全測試工具箱中的得力助手！🛡️**
