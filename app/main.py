"""FastAPI application: dangerous-goods custody chain API."""
from __future__ import annotations

import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import ValidationError

from . import config, evidence, services
from .database import connect, init_db
from .schemas import (
    BatchResponse,
    BatchSubmit,
    ChainResponse,
    ProofResponse,
    SealResponse,
    VerifyRequest,
    VerifyResponse,
    WaybillCreate,
    WindowRequest,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> None:
    init_db()
    yield


app = FastAPI(
    title="空运危险品保管链 API",
    description=(
        "运单保管链（扫描交接 / 撤回 / 补报 / 更正）的修订裁决与可信前缀查询。"
        "同 ID 仅最高修订生效；同修订异文整批拒绝；失败保留旧链。"
    ),
    version="1.0.0",
    lifespan=lifespan,
)


def get_conn() -> sqlite3.Connection:  # type: ignore[return]
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Error mapping: domain errors never leak 500s, and failed batches have
# already been rolled back by the service layer.
# --------------------------------------------------------------------------- #
@app.exception_handler(services.DomainConflict)
async def conflict_handler(_: Request, exc: services.DomainConflict) -> JSONResponse:
    return JSONResponse(status_code=409, content={"error": "conflict", "detail": str(exc)})


@app.exception_handler(services.DomainValidation)
async def not_found_handler(_: Request, exc: services.DomainValidation) -> JSONResponse:
    return JSONResponse(status_code=404, content={"error": "not_found", "detail": str(exc)})


@app.exception_handler(ValidationError)
async def pydantic_handler(_: Request, exc: ValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"error": "validation_error", "detail": exc.errors()})


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #
@app.post("/api/waybills", status_code=201, tags=["waybills"])
def create_waybill(
    body: WaybillCreate, conn: sqlite3.Connection = Depends(get_conn)
) -> dict:
    """创建运单并固定其起始保管方。"""
    return services.create_waybill(conn, body)


@app.get("/api/waybills", tags=["waybills"])
def list_waybills(conn: sqlite3.Connection = Depends(get_conn)) -> dict:
    rows = conn.execute(
        "SELECT id, origin_party, created_at FROM waybills ORDER BY id"
    ).fetchall()
    return {"waybills": [dict(r) for r in rows]}


@app.post(
    "/api/waybills/{waybill_id}/scans/batch",
    response_model=BatchResponse,
    tags=["scans"],
)
def submit_batch(
    waybill_id: str,
    batch: BatchSubmit,
    conn: sqlite3.Connection = Depends(get_conn),
) -> BatchResponse:
    """批量提交交接/撤回。

    * HANDOVER：scan_id、revision、ts_utc（带时区）、giver、receiver
    * WITHDRAWAL：仅 scan_id、revision（必须高于已知最高修订）
    * 同修订异文、过期修订、撤回未知 ID -> 409，整批回滚，旧链保留
    """
    return services.apply_batch(conn, waybill_id, batch)


@app.get(
    "/api/waybills/{waybill_id}/chain",
    response_model=ChainResponse,
    tags=["scans"],
)
def query_chain(
    waybill_id: str, conn: sqlite3.Connection = Depends(get_conn)
) -> ChainResponse:
    """返回可信连续交接前缀、首处断链原因与当前可确认保管方。"""
    return services.compute_chain(conn, waybill_id)


# --------------------------------------------------------------------------- #
# Evidence seals, time-window proofs, offline verification
# --------------------------------------------------------------------------- #
@app.post(
    "/api/waybills/{waybill_id}/seals",
    response_model=SealResponse,
    status_code=201,
    tags=["evidence"],
)
def seal_waybill(
    waybill_id: str, conn: sqlite3.Connection = Depends(get_conn)
) -> SealResponse:
    """按运单封存当前已提交状态的可信前缀与首处断链时刻。

    封存是不可变快照：之后的补报、更正、撤回或重启都不影响该封存，
    仍可用原封存号与原摘要出证。返回封存号及可另行留存的稀疏摘要。
    """
    return evidence.create_seal(conn, waybill_id)


@app.get(
    "/api/waybills/{waybill_id}/seals/{seal_id}",
    response_model=SealResponse,
    tags=["evidence"],
)
def get_seal(
    waybill_id: str, seal_id: str, conn: sqlite3.Connection = Depends(get_conn)
) -> SealResponse:
    """读取封存元数据与封存时签发的全部可留存摘要。"""
    return evidence.get_seal(conn, waybill_id, seal_id)


@app.post(
    "/api/waybills/{waybill_id}/proofs",
    response_model=ProofResponse,
    tags=["evidence"],
)
def issue_proof(
    waybill_id: str,
    req: WindowRequest,
    conn: sqlite3.Connection = Depends(get_conn),
) -> ProofResponse:
    """凭封存号与 UTC 半开时间窗 [start, end) 申请核查证明。

    * 窗内存在已证实交接 → ``HAS_RECORD``；
    * 窗内无记录但窗尾晚于首处断链时刻 → ``INSUFFICIENT_EVIDENCE``；
    * 其余 → ``EMPTY_WINDOW``，仅附断链界限与窗外紧邻交接。
    """
    return evidence.issue_proof(conn, waybill_id, req)


@app.post(
    "/api/verify",
    response_model=VerifyResponse,
    tags=["evidence"],
)
def verify_proof(req: VerifyRequest) -> VerifyResponse:
    """凭留存摘要、运单号、封存号、时间窗与证明离线验真，不读取原库。"""
    return evidence.verify_proof(req)


# --------------------------------------------------------------------------- #
# Minimal console (the interactive /docs remains fully functional too).
# --------------------------------------------------------------------------- #
_STATIC_DIR = Path(__file__).parent / "static"


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")
