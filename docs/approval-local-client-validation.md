# Approval / Local Client 重構驗證紀錄

更新日期：2026-10-17（Asia/Shanghai）。分支：`refactor/function-approval-local-client`。
主 Plan 23764；Generic Approval 23765；Local Client 23766。Conversation 120；writer_nonce 沿用交接文件。

**實作已補齊；Windows 原生 client matrix 及 Linux 五項真實 Bubblewrap／RootlessKit 驗證通過。macOS／Linux 最終全套與 Windows client matrix 均通過，遠端 CI 未執行。未 commit、push 或部署。**

## 已完成的實作

- Files 的公開 approval request 改用通用 FunctionGrants；Server 儲存／轉交 opaque auth，Client 的 `files.read`／`files.write` callback 決定生成、合併、重用與執行範圍。舊 Mapping Client 缺少此能力時明確要求升級；一般未授權模式的既有 File RPC 保留。
- 可省略 `approval_prepare`；存在時只呼叫一次，採用 Client 回傳的 request/display。未宣告時不送 prepare RPC。只有內部協議能執行 prepare/grant。
- 密碼驗證之前不解析檔案真實路徑；Client 在 grant callback 解析 canonical scope，Browser 顯示 Client proposal，再由同一個驗證過密碼的瀏覽器確認。確認時重新計算並比對 proposal／舊 auth revision，避免 symlink 換向或並行授權覆蓋。
- Native File API、原始二進位讀寫、MCP binary read、recycle list/restore/purge 均透過 Local Client 入口執行，共用 FileExecutionMixin 引擎。原有 Mapping／Storage Provider、索引、ETag、atomic mutation 與傳輸引擎保留。
- Mapping File 函數在 Client 執行，支援多個外部 scope、讀寫分離、symlink／traversal 檢查、deny/protect/ro/rw、全域設定檔及外部 sandbox deny 保護。
- 批准後的 Mapping binary stream 使用私有函數與 Client descriptor；固定 transport generation，不重播不確定的寫入，descriptor 只屬於該 Client RPC session。覆蓋大於一個 RPC chunk 的上傳、SHA-256、禁止覆蓋、Range、HEAD 與條件 ETag 讀取。
- 修正 reason 驗證、每票密碼嘗試上限、Token/Mapping 二次綁定檢查、舊 Admin Shell revoke 相容性，以及密碼驗證／撤銷之間的鎖順序衝突。回呼期間到期或撤銷不會重新產生授權。
- Source fingerprint 已涵蓋新共用／Client／Server 模組；CI client matrix 加入新的 FunctionRegistry、FunctionGrants、Files 與 Local Client 測試。

## 驗證結果

| 項目 | 結果 | 證據／限制 |
| --- | --- | --- |
| 分支、既有修改保留 | 通過 | 在原工作樹接續；未 reset、checkout、stash、commit、push |
| git diff --check | 通過 | 最後一次檢查 exit 0 |
| compileall（openkapsel、openkapsel_runtime、tests） | 通過 | macOS Python 3.14；CI YAML 亦成功解析 |
| 四個原新增測試模組 | 通過 | 首輪 13 項；現已增加並行／到期／撤銷測試 |
| Generic／Files／Local Client 新測試 | 通過 | 原 30 項加 3 項 File/Windows 與 1 項 RootlessKit process 回歸，共 34 項；依平台適用性執行 |
| 交接要求的既有回歸模組 | 通過 | 均包含於最終完整 discover；保留行為與安全斷言 |
| macOS 最終完整測試 | 通過，有平台跳過 | **888 項：875 通過、13 跳過、0 失敗、0 錯誤**；255.229 秒；task `&kSer&` |
| Linux 隔離環境聚焦測試 | 通過 | 最終來源的新增／Runtime／Storage OAuth／Provider recycle 合計 **44 項，0 失敗、0 跳過** |
| Linux 隔離環境完整測試嘗試 | 未通過，環境受限 | 初次 snapshot：877 項，3 失敗、42 錯誤、23 跳過；AF_UNIX socket 建立被執行環境拒絕（EPERM），造成 Manager／Proxy 相關失敗；當時缺少 sqlalchemy/httpx 的 4 個 import／OAuth 錯誤已在安裝專案依賴後通過 44 項聚焦重驗 |
| 原生 Linux 五項真實隔離 | 通過 | **5/5，無跳過**；既有非 root `openkapsel` 身份，隔離的 /tmp 測試副本；最終 2.887 秒 |
| 原生 Linux 最終完整測試 | 通過，有平台跳過 | **888 項：865 通過、23 跳過、0 失敗、0 錯誤**；766.926 秒；Python 3.12；task `&5AJc&` exit 0；相同 manifest，獨立非 root venv |
| 原生 Windows client matrix＋config lock | 通過，有平台跳過 | **183 項：145 通過、38 跳過、0 失敗／錯誤**；12.624 秒；Python 3.11；task `&rbdI&` |
| GitHub CI／不同 Python 與 Linux distro matrix | 尚未執行 | 遵照不 push 指示；沒有建立提交或觸發遠端 CI |

原始 148 項回歸首輪曾有 22 失敗、2 錯誤，已修復。完整測試第一次 879 項的唯一錯誤為 Provider recycle 測試假 Server 未提供 Local Client；已補真實 LocalClient 入口，保留全部 Provider／server-bin 斷言。macOS 路徑包含 `/private`，新增 deny 測試改為精確檢查 entries 名稱及直接讀取拒絕，不以整份結果字串誤判。

## macOS 的 13 項跳過（不是通過）

Windows 原生語義 8 項（均已在 Windows 實際通過）：

- `test_client_config_lock.ClientConfigLockTests.test_windows_lock_denies_other_process_read_access`
- `test_client_windows.WindowsClientTests.test_files_and_recycle`
- `test_client_windows.WindowsClientTests.test_junction_and_special_paths_are_denied`
- `test_client_windows.WindowsClientTests.test_native_task_uses_configured_directory`
- `test_windows_powershell_policy.PowerShellFilesystemTests.test_windows_file_rpc_and_native_guard_also_reject_devices_and_ads`
- `test_windows_powershell_policy.WindowsApprovalTasksTests.test_windows_file_rpc_and_native_guard_also_reject_devices_and_ads`

- `test_file_function_approval.FileFunctionTests.test_windows_scope_ancestor_junction_swap_cannot_redirect_io`
- `test_file_function_approval.FileFunctionTests.test_windows_approved_paths_reject_devices_and_ads_before_resolution`

Linux 真實 Bubblewrap／namespace／Manager 5 項（均已在原生 Linux 實際通過）：

- `test_client_job_sandbox.ClientJobSandboxTests.test_linux_short_shell_really_uses_manager_and_write_grants`
- `test_job_sandbox.JobSandboxTests.test_bubblewrap_cannot_reach_manager_unix_socket`
- `test_job_sandbox.JobSandboxTests.test_bubblewrap_real_filesystem_network_and_hidden_files`
- `test_job_sandbox.JobSandboxTests.test_manager_bubblewrap_survives_early_ipc_thread_exit`
- `test_sandbox_verify.SandboxVerificationTests.test_real_bubblewrap_enforces_private_files_pid_and_readonly`

已安裝開發環境的可選 YAML、TOML、Excel parser，這些測試在最終 macOS run 已實際執行，沒有以 optional-dependency skip 算通過。

## 功能級驗收對照交接文件

| 交接項目 | 結果 |
| --- | --- |
| 1. 只有 execute 的函數 | 通過：FunctionRegistry 單元測試 |
| 2. 可選 prepare | 通過：無 prepare、prepare 一次、轉換 request、拒絕 grant 的真實 HTTP 測試 |
| 3. Client 自行合併 auth | 通過：兩個外部目錄在真實 WebSocket 上累積並各自可讀；父 scope 合併子 scope 由 Client 處理 |
| 4. Browser Approval | 通過：CSRF、密碼、嘗試限制、一次性、UTM query、二次確認、同瀏覽器綁定 |
| 5. Server Local Client | 通過：Shell／RPC／File／binary／recycle；888 項完整回歸 |
| 6. Mapping Client | 通過：真實 WebSocket Files／Shell／授權串流；Windows 原生 183 項已通過 |
| 7. Files 安全範圍 | macOS／Linux 聚焦與 Windows 原生均通過，含多 scope、junction 換向／祖先競態、device／ADS 解析前拒絕 |
| 8. 隔離、到期、撤銷 | 通過：Workspace／Conversation／target／function 隔離、密碼重設、callback 撤銷、並行確認不覆蓋新授權 |
| 9. 公開介面 | 通過：私有 callback 不作為 public RPC；對私有 grant 的公開 RPC 嘗試被拒絕；Discovery 說明已保留 |
| 10. 功能回歸 | macOS 完整及 Windows client 通過；Linux 真實 sandbox 5/5，最終完整回歸 888 項通過 |

## 日誌與重跑

macOS 原工作樹的日誌：

- 最終完整：`/tmp/openkapsel-refactor-complete.log`（888 項通過）
- 初輪完整：`/tmp/openkapsel-refactor-verified.log`（884 項通過）
- 880 項完整通過（並行補測之前）：`/tmp/openkapsel-refactor-full-final.log`
- HTTP／Browser／WebSocket：`/tmp/openkapsel-acceptance.log`
- 早期完整與修正歷史：`/tmp/openkapsel-refactor-full.log`、`/tmp/openkapsel-files-http.log`

本次 AI 隔離 Linux 環境的日誌：

- `/tmp/openkapsel-linux-full.log`（受限環境的完整失敗紀錄）
- `/tmp/openkapsel-linux-confirmed.log`（補依賴後最終來源 44 項通過）
- `/tmp/openkapsel-linux-files-final.log`（File／parallel RPC 聚焦）
- `/tmp/openkapsel-linux-stream.log`（真實 WebSocket stream）

## 原生驗證與最新修正

使用者已完成 Windows 與 Linux 的目標專屬授權。測試均在獨立目錄或臨時副本執行；沒有更動服務、主機 UID/GID 配置或生產目錄權限。

- Windows 發現並修復：ApprovedFiles 誤用 POSIX 存取器；Local Client 未選 Windows provider；stream stat/unlink 的原生分流；multi-root anchor 回傳契約；canonical scope 祖先 junction 換向競態；device/ADS 等名稱在真實路徑解析前拒絕。
- Windows 舊 PowerShell 測試需建立 symlink 的權限。保留 POSIX symlink 測試，Windows 改用真實 junction 夾具並保留拒絕讀取、任務不啟動等全部斷言；不修改主機安全設定。Config secrecy 測試改用 Windows 正式 provider，保留全部內容不可見／不可變斷言。
- 真實 Linux 發現 RootlessKit 3.0.2 會關閉所有繼承 extra FD，造成 Bubblewrap resolver `Bad file descriptor`。修正為在 RootlessKit exec 邊界後建立 DNS descriptor；保留 stdin、mount、network、socket 與 Manager 私密狀態的隔離。新增跨 process 測試模擬關閉全部 extra FD，檢查 DNS 與 caller stdin；既有 FD 3 測試不變。
- 原生 Shell 以 root 進入時沒有 root 的 subuid/subgid 範圍，不能作為 RootlessKit 的有效驗收環境。最終使用既有 `openkapsel` 非 root 帳號及其現有範圍，在該帳號擁有的 /tmp 來源＋venv 副本驗證；未更改任何帳號或範圍。

程式與測試共 **231 檔**，三平台以相對路徑及每檔 SHA-256 建立 manifest；最終 canonical manifest SHA-256：

`6f5bee47899f88495dbcf7c69fce21aea79dacbb7b138601fc56bc74968e08fe`

最初 ZIP（287 檔）SHA-256 為 `2bd3120e8fb81f215af070c3907956bac87538234c5e718b37b56ac538321d10`，其後同步上述修正；不可把初始 ZIP hash 當成最終程式內容的證明。

原生測試目錄與日誌：

- Windows：`moe/tmp/openkapsel-refactor-validation-20261017`；最終 `tests-final-accepted.log`、`final-manifest.json`，獨立 `test-venv`。cmd 執行，不使用 PowerShell 的 `&` 前綴。
- Linux：`kapsel/refactor-validation-20261017`；`verify_complete.py`、`final-manifest.json`、`preflight-complete.log`、`real-sandbox-complete.log`、`all-tests-complete.log` 與 `complete-result.json`（real_sandbox_exit=0、tests_exit=0）；前一輪 `real-sandbox-accepted.log` 已 5/5 通過，`tests-accepted.log` 保留依賴缺口的真實結果。
- macOS：原工作樹；最終來源執行 `/tmp/openkapsel-refactor-complete.log`（task `&kSer&`，888 項通過）。上一輪 Windows 修正後、RootlessKit 修正前的 887 項全套已通過。

Windows 的 38 項跳過（不是通過）：

| 原因 | 項數 |
| --- | --- |
| real Client-to-Manager Bubblewrap runs in dedicated Linux CI | 1 |
| Real Seatbelt integration requires macOS | 2 |
| uses macOS native Seatbelt sandbox | 1 |
| server API is not supported on Windows | 2 |
| server-side transfers require Linux/POSIX | 2 |
| POSIX descriptor tests; see test_client_windows | 21 |
| POSIX openat no-follow traversal | 1 |
| POSIX client realpath approval protocol | 1 |
| POSIX symlink path test | 1 |
| POSIX external directory paths | 1 |
| symlink creation may require Windows developer mode | 1 |
| symlinks unavailable on this host | 1 |
| symlink privilege differs on Windows | 1 |
| POSIX sparse seek fixture; do not allocate 10 GiB on Windows | 1 |
| Server Shell executor is POSIX-only | 1 |

CI client matrix 已加入 Function/File/Local Client 契約以及 config lock/secrecy 回歸。Hosted GitHub Actions／Linux Python 3.10、3.14 與 distro matrix 尚未執行，遵守使用者不 commit／push 的指示。三個 Plan（23764、23765、23766）以本次授權範圍結案：實作、回歸及原生端到端驗證完成。Hosted CI／Python／distro matrix 延後至使用者另行授權 commit／push 後執行，不作為本次結案的阻塞條件。

## 最終 Linux 結果與失敗處理

- `complete-result.json` 確認完整測試及真實 sandbox 的 exit code 均為 0；來源 manifest 與最終 macOS／Windows 一致。
- 補依賴前同來源完整測試曾有 3 失敗、2 錯誤、23 跳過（874.261 秒）：兩個 live watcher 斷言因缺 watchfiles 失敗、兩個 Runtime 測試因缺 FastAPI 錯誤，另一次 WebSocket ready 握手中斷。保留全部斷言與 timeout；在獨立測試 venv 補齊依賴後，6 項先驗及完整 888 項均通過，WebSocket 中斷未在最終全套重現。舊 `tests-accepted.log`／`accepted-result.json` 保留失敗，不能當成最終結果。
- 受限 AI Linux 執行環境的 AF_UNIX／Manager 失敗仍是該環境限制；已由原生 Linux 的完整測試、真實 Browser／WebSocket／串流與五項隔離結果補齊驗證。
- 交付前再透過 File API 對原 macOS 工作樹 **231 個程式及測試檔案**逐檔計算 SHA-256，全部與通過測試的 manifest 相同，沒有測試後的來源漂移。Git RPC 再確認目前分支與 28 個 tracked 修改／16 個 untracked 檔案；原有修改保留。

Linux discover 的 23 項跳過分類如下；Windows 8 項已在 Windows 通過、macOS 10 項已在 macOS 通過，Linux opt-in 真實隔離 5 項已另以專用命令實際通過，不把 discover 的 skip 算作 pass。

| 原因 | 項數 |
| --- | --- |
| Windows sharing-denial semantics | 1 |
| real Client-to-Manager Bubblewrap runs in dedicated Linux CI | 1 |
| Real Seatbelt integration requires macOS | 2 |
| Windows native handles required | 3 |
| Windows device and ADS paths | 1 |
| Windows native junction race | 1 |
| requires real Linux Bubblewrap installation and namespaces | 1 |
| real Job Manager Bubblewrap runs in dedicated Linux CI | 1 |
| requires real Linux Bubblewrap and a running Job Manager | 1 |
| requires actual macOS Seatbelt | 2 |
| macOS Seatbelt is required | 4 |
| Only Seatbelt is configured on macOS | 1 |
| uses macOS native Seatbelt sandbox | 1 |
| actual Linux Bubblewrap isolation runs in dedicated CI job | 1 |
| requires native WindowsPaths | 2 |

最終無尚未修復的測試失敗。尚未執行：GitHub Actions、Linux Python 3.10／3.14 與不同 distro matrix。遵守使用者指示，未 commit、push、部署或改動主機安全設定。
