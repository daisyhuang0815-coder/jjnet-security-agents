#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JJNET MSSP Platform - GitHub Deployment Script
支援：
1. 100% 純 Python 透過 GitHub Git Database API 建立 Repo 與 Commit (無須安裝本機 git.exe，零依賴)
2. 本機 Git CLI 雙軌支援
"""

import os
import sys
import json
import base64
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

# 設定 Windows 終端機 UTF-8
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

PROJECT_DIR = Path(__file__).resolve().parent.parent

# 忽略檔案清單
IGNORED_PATTERNS = {
    '.git', '__pycache__', '.env', '.DS_Store', 'Thumbs.db',
    'jjnet-security-agents-dist.zip'
}

def is_ignored(path: Path) -> bool:
    for part in path.parts:
        if part in IGNORED_PATTERNS or part.endswith('.pyc'):
            return True
    return False

def collect_project_files(base_dir: Path):
    """收集專案中所有需納入版本控管的檔案"""
    file_map = {}
    for p in base_dir.rglob('*'):
        if p.is_file() and not is_ignored(p.relative_to(base_dir)):
            rel_path = str(p.relative_to(base_dir)).replace('\\', '/')
            file_map[rel_path] = p
    return file_map

def find_git_executable():
    """尋找本機是否有 git 可執行檔"""
    candidates = [
        "git",
        r"C:\Program Files\Git\cmd\git.exe",
        r"C:\Program Files\Git\bin\git.exe",
        r"C:\Program Files (x86)\Git\cmd\git.exe",
        str(Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Git" / "cmd" / "git.exe")
    ]
    for c in candidates:
        try:
            res = subprocess.run([c, "--version"], capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                return c
        except Exception:
            continue
    return None

def github_api_request(url, token, data=None, method="GET"):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "JJNET-Deploy-Agent",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    req_data = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")
        try:
            return e.code, json.loads(err_msg)
        except Exception:
            return e.code, {"message": err_msg}
    except Exception as ex:
        return 500, {"message": str(ex)}

def deploy_via_git_api(token, username, repo_name, commit_message="Initial commit: JJNET Sovereign Cybersecurity Multi-Agent Platform"):
    """
    100% 純 Python 透過 GitHub Git Database API 建立 Commit 與更新 main 分支
    無須安裝本機 git.exe，支援所有檔案 (包含 .docx, .jpg, 程式碼)
    """
    print("\n🌐 啟動純 Python GitHub Git Database API 上傳引擎 (零本機軟體依賴)...")

    files = collect_project_files(PROJECT_DIR)
    print(f"📦 掃描到 {len(files)} 個專案檔案準備上傳...")

    # 1. 取得 parent commit
    ref_url = f"https://api.github.com/repos/{username}/{repo_name}/git/refs/heads/main"
    ref_status, ref_data = github_api_request(ref_url, token)
    parent_commit_sha = None
    base_tree_sha = None

    if ref_status == 200:
        parent_commit_sha = ref_data.get("object", {}).get("sha")
        if parent_commit_sha:
            _, commit_data = github_api_request(f"https://api.github.com/repos/{username}/{repo_name}/git/commits/{parent_commit_sha}", token)
            base_tree_sha = commit_data.get("tree", {}).get("sha")

    # 2. 逐一上傳 Blobs
    tree_items = []
    print("📤 正在上傳檔案 Blobs...")
    for idx, (rel_path, abs_path) in enumerate(files.items(), 1):
        try:
            with open(abs_path, "rb") as f:
                content_bytes = f.read()
            b64_content = base64.b64encode(content_bytes).decode("ascii")
            blob_payload = {
                "content": b64_content,
                "encoding": "base64"
            }
            blob_status, blob_data = github_api_request(
                f"https://api.github.com/repos/{username}/{repo_name}/git/blobs",
                token,
                data=blob_payload,
                method="POST"
            )
            if blob_status not in (200, 201):
                print(f"  ❌ [{idx}/{len(files)}] 上傳失敗: {rel_path} - {blob_data.get('message')}")
                return False

            tree_items.append({
                "path": rel_path,
                "mode": "100644",
                "type": "blob",
                "sha": blob_data["sha"]
            })
            print(f"  ✓ [{idx}/{len(files)}] {rel_path} ({len(content_bytes)} bytes)")
        except Exception as e:
            print(f"  ❌ [{idx}/{len(files)}] 讀取失敗 {rel_path}: {e}")
            return False

    # 3. 建立 Git Tree
    print("\n🌲 正在向 GitHub 登記 Git Tree 結構...")
    tree_payload = {"tree": tree_items}
    if base_tree_sha:
        tree_payload["base_tree"] = base_tree_sha

    tree_status, tree_data = github_api_request(
        f"https://api.github.com/repos/{username}/{repo_name}/git/trees",
        token,
        data=tree_payload,
        method="POST"
    )
    if tree_status not in (200, 201):
        print(f"❌ 建立 Git Tree 失敗: {tree_data.get('message')}")
        return False
    new_tree_sha = tree_data["sha"]
    print(f"  ✓ Git Tree 建立成功: {new_tree_sha[:8]}...")

    # 4. 建立 Commit
    print("📝 正在向 GitHub 提交 Commit...")
    commit_payload = {
        "message": commit_message,
        "tree": new_tree_sha,
        "parents": [parent_commit_sha] if parent_commit_sha else []
    }
    commit_status, commit_data = github_api_request(
        f"https://api.github.com/repos/{username}/{repo_name}/git/commits",
        token,
        data=commit_payload,
        method="POST"
    )
    if commit_status not in (200, 201):
        print(f"❌ 建立 Commit 失敗: {commit_data.get('message')}")
        return False
    new_commit_sha = commit_data["sha"]
    print(f"  ✓ Commit 建立成功: {new_commit_sha[:8]}...")

    # 5. 更新 main 分支 Ref
    print("🚀 正在設定 main 分支指針...")
    if parent_commit_sha:
        ref_update_status, ref_update_data = github_api_request(
            f"https://api.github.com/repos/{username}/{repo_name}/git/refs/heads/main",
            token,
            data={"sha": new_commit_sha, "force": True},
            method="PATCH"
        )
    else:
        ref_update_status, ref_update_data = github_api_request(
            f"https://api.github.com/repos/{username}/{repo_name}/git/refs",
            token,
            data={"ref": "refs/heads/main", "sha": new_commit_sha},
            method="POST"
        )

    if ref_update_status in (200, 201):
        print("  ✓ main 分支已成功指向最新 Commit！")
        return True
    else:
        print(f"❌ 分支更新失敗: {ref_update_data.get('message')}")
        return False

def deploy_to_github(token, repo_name="jjnet-security-agents", is_private=False, description=None):
    token = token.strip()
    if not description:
        description = "JJNET Cyber SOC Multi-Agent & RAG Platform (Sovereign Local AI & Autonomous CLI)"

    print("\n" + "="*70)
    print("🚀 【JJNET 專案部署至 GitHub】")
    print("="*70)

    # 1. 驗證 Token 並取得使用者名稱
    print("🔑 正在驗證 GitHub Personal Access Token...")
    status, user_info = github_api_request("https://api.github.com/user", token)
    if status != 200:
        print(f"❌ Token 驗證失敗 (HTTP {status}): {user_info.get('message', '未知錯誤')}")
        print("💡 請確認您的 Token 是否有效並具備 'repo' 讀寫權限。")
        return False

    username = user_info.get("login")
    display_name = user_info.get("name") or username
    print(f"✅ 成功驗證 GitHub 帳號: \033[92m{username}\033[0m ({display_name})")

    # 2. 檢查或建立 Repository
    print(f"📦 正在檢查 Repository [{repo_name}]...")
    check_status, check_data = github_api_request(f"https://api.github.com/repos/{username}/{repo_name}", token)

    if check_status == 200:
        print(f"ℹ️  遠端 Repository [{repo_name}] 已存在，將更新程式碼。")
    else:
        print(f"✨ 正在為您在 GitHub 建立全新 Repository [{repo_name}] (私有: {is_private})...")
        create_payload = {
            "name": repo_name,
            "description": description,
            "private": is_private,
            "auto_init": False
        }
        create_status, create_data = github_api_request("https://api.github.com/user/repos", token, data=create_payload, method="POST")
        if create_status in (200, 201):
            print(f"✅ Repository 建立成功: \033[96m{create_data.get('html_url')}\033[0m")
        else:
            print(f"❌ 建立 Repository 失敗 (HTTP {create_status}): {create_data.get('message')}")
            return False

    # 3. 嘗試本機 Git 或純 Python Git Database API
    git_bin = find_git_executable()
    if git_bin:
        print(f"🔧 偵測到本機 Git: {git_bin}，執行本機 Git 推送...")
        user_email = user_info.get("email") or f"{username}@users.noreply.github.com"
        subprocess.run([git_bin, "init"], cwd=str(PROJECT_DIR), capture_output=True)
        subprocess.run([git_bin, "config", "user.name", username], cwd=str(PROJECT_DIR), capture_output=True)
        subprocess.run([git_bin, "config", "user.email", user_email], cwd=str(PROJECT_DIR), capture_output=True)
        subprocess.run([git_bin, "branch", "-M", "main"], cwd=str(PROJECT_DIR), capture_output=True)
        subprocess.run([git_bin, "add", "-A"], cwd=str(PROJECT_DIR), capture_output=True)
        subprocess.run([git_bin, "commit", "-m", "Initial commit: JJNET Sovereign Cybersecurity Multi-Agent Platform"], cwd=str(PROJECT_DIR), capture_output=True)
        remote_url = f"https://{username}:{token}@github.com/{username}/{repo_name}.git"
        subprocess.run([git_bin, "remote", "remove", "origin"], cwd=str(PROJECT_DIR), capture_output=True)
        subprocess.run([git_bin, "remote", "add", "origin", remote_url], cwd=str(PROJECT_DIR), capture_output=True)
        push_res = subprocess.run([git_bin, "push", "-u", "origin", "main", "--force"], cwd=str(PROJECT_DIR), capture_output=True, text=True)
        if push_res.returncode == 0:
            success = True
        else:
            print(f"⚠️ 本機 Git 推送遭遇阻礙，自動切換為純 Python Git API 上傳...")
            success = deploy_via_git_api(token, username, repo_name)
    else:
        # 直接使用純 Python Git Database API
        success = deploy_via_git_api(token, username, repo_name)

    if success:
        html_url = f"https://github.com/{username}/{repo_name}"
        print("\n" + "="*70)
        print("🎉 \033[92m專案已成功完整部署到 GitHub！\033[0m")
        print(f"🔗 儲存庫網址: \033[96m\033[1m{html_url}\033[0m")
        print(f"🔒 可見度: {'Private (私有)' if is_private else 'Public (公開)'}")
        print("="*70 + "\n")
        return True
    return False

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Deploy JJNET platform to GitHub")
    parser.add_argument("--token", help="GitHub Personal Access Token (PAT)")
    parser.add_argument("--repo", default="jjnet-security-agents", help="Repository 名稱 (預設: jjnet-security-agents)")
    parser.add_argument("--private", action="store_true", help="建立為私有 (Private) 儲存庫")
    args = parser.parse_args()

    token = args.token or os.environ.get("GITHUB_TOKEN")
    if not token:
        token = input("請輸入您的 GitHub Personal Access Token (PAT): ").strip()

    if not token:
        print("❌ 未提供 Token，取消操作。")
        sys.exit(1)

    success = deploy_to_github(token, repo_name=args.repo, is_private=args.private)
    sys.exit(0 if success else 1)
