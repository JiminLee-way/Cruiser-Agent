"""调度器冒烟测试：stub `claude` + 静态目标题，跑完整的 main.py --sessions 2 流水线。

stub 按真实 claude CLI 的 stream-json 形态输出：assistant 事件里的 Bash tool_use 调用
提示词中给出的 submit_flag.py 命令（并真的执行它），随后输出 user(tool_result) 与 result。
验证：题目被本地平台记为解出、调度器打印退出信息并以 0 退出。
"""
from __future__ import annotations

import http.server
import json
import os
import stat
import subprocess
import sys
import textwrap
import threading

import pytest

from conftest import subprocess_env

FLAG = "flag{smoke_test_static_target}"

STUB = textwrap.dedent('''\
    #!{python}
    import json, os, re, subprocess, sys
    args = sys.argv[1:]
    prompt = args[args.index("-p") + 1]
    code = os.environ["CRUISER_CHALLENGE_CODE"]
    flag = os.environ["STUB_FLAG"]
    m = re.search(r'("[^"]+" \\S+submit_flag\\.py)', prompt)
    cmd = f"{{m.group(1)}} {{code}} '{{flag}}'"

    def emit(obj):
        print(json.dumps(obj, ensure_ascii=False), flush=True)

    emit({{"type": "system", "subtype": "init"}})
    emit({{"type": "assistant", "message": {{"content": [
        {{"type": "text", "text": "找到 flag，提交"}},
        {{"type": "tool_use", "id": "t1", "name": "Bash", "input": {{"command": cmd}}}},
    ]}}}})
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
    emit({{"type": "user", "message": {{"content": [
        {{"type": "tool_result", "tool_use_id": "t1", "content": out}},
    ]}}}})
    emit({{"type": "result", "subtype": "success"}})
''')


@pytest.fixture
def http_target():
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_main_sessions_2_solves_static_challenge(repo_copy, tmp_path, http_target):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "claude"
    stub.write_text(STUB.format(python=sys.executable))
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)

    yaml_path = tmp_path / "challenges.yaml"
    yaml_path.write_text(textwrap.dedent(f"""
        challenges:
          - code: SMOKE-1
            difficulty: easy
            description: smoke test
            flags: ["{FLAG}"]
            target: {http_target}
    """))

    env = subprocess_env(
        PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        CRUISER_CHALLENGES=str(yaml_path),
        CRUISER_DASHBOARD="0",
        CRUISER_CONTAINER_WARMUP="10",
        STUB_FLAG=FLAG,
        DEEPSEEK_API_KEY="sk-fake-for-tests",
        # watcher / [flag方法] 的 LLM 请求打到关闭的端口，快速失败、不出网
        DEEPSEEK_BASE_URL="http://127.0.0.1:9/v1",
        ANTHROPIC_BASE_URL="http://127.0.0.1:9/anthropic",
        CRUISER_LOG_FILE=str(tmp_path / "cruiser.log"),
    )
    env.pop("ANTHROPIC_AUTH_TOKEN", None)
    proc = subprocess.run(
        [sys.executable, "-u", "./main.py", "--sessions", "2"],
        cwd=str(repo_copy), env=env, capture_output=True, text=True, timeout=180,
    )
    out = proc.stdout + proc.stderr
    print(out)
    assert proc.returncode == 0, out[-4000:]
    assert "[Stage-Preprocess] 启动 SMOKE-1" in out
    assert "[SMOKE-1:S1]" in out and "[COUNT] 1" in out
    assert "[SUBMIT_FLAG][OK] 提交正确，flag 进度 1/1" in out
    assert "全部 flag 已齐 (1/1)" in out
    assert "[SMOKE-1] [STAGE] 平台 flag 进度 1/1，结束本轮" in out
    assert "全部题目已解出，退出" in out

    state = json.loads((repo_copy / "reports" / "_platform_state.json").read_text())
    assert state["challenges"]["SMOKE-1"]["solved"] == [0]
    assert (repo_copy / "reports" / "desc_SMOKE-1.txt").read_text() == "smoke test"
