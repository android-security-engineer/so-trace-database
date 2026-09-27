import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.trace import Trace, Instruction, CallTrace, MemoryDelta, RegisterState, JniCall
from models.so_file import SoFile
from middleware.auth import require_auth

router = APIRouter(prefix="/traces", tags=["traces"])


class TraceOut(BaseModel):
    id: int
    so_file_id: Optional[int]
    so_file_name: str
    instruction_count: int
    call_count: int
    memory_delta_count: int
    created_at: float

    model_config = {"from_attributes": True}


class InstructionOut(BaseModel):
    seq: int
    thread_id: int
    address: int
    is_branch: bool
    branch_taken: bool
    timestamp: Optional[int] = None
    opcode: Optional[str] = None


class CallTraceOut(BaseModel):
    id: int
    thread_id: int
    event_type: str
    caller_address: int
    callee_address: int
    callee_func_name: Optional[str] = None
    seq: int
    depth: int


class MemoryDeltaOut(BaseModel):
    id: int
    seq: int
    thread_id: int
    page_address: int
    delta_type: str
    prev_content_hash: str


class MemoryValueOut(BaseModel):
    address: int
    value: list[int]
    size: int


class RegisterStateOut(BaseModel):
    seq: int
    gp_regs: list[int]
    sp: int
    pc: int
    nzcv: int


class JniCallOut(BaseModel):
    id: int
    seq: int
    thread_id: int
    direction: str
    java_class: str
    java_method: str
    java_signature: str
    native_address: int


class StackFrameOut(BaseModel):
    func_name: Optional[str] = None
    entry_address: int
    call_site: int
    call_seq: int
    depth: int


@router.get("", response_model=list[TraceOut])
async def list_traces(db: AsyncSession = Depends(get_db), _=Depends(require_auth)):
    result = await db.execute(select(Trace).order_by(Trace.created_at.desc()))
    return [_trace_out(t) for t in result.scalars().all()]


@router.get("/{trace_id}", response_model=TraceOut)
async def get_trace(trace_id: int, db: AsyncSession = Depends(get_db), _=Depends(require_auth)):
    t = await db.get(Trace, trace_id)
    if not t:
        raise HTTPException(status_code=404, detail="Not found")
    return _trace_out(t)


@router.post("/import", response_model=TraceOut, status_code=201)
async def import_trace(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    _=Depends(require_auth),
):
    content = await file.read()
    try:
        data = json.loads(content)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON trace file")

    so_file_name = data.get("so_file", file.filename or "unknown")
    so_file_id = None

    if so_name := data.get("so_file"):
        so = await db.scalar(select(SoFile).where(SoFile.path == so_name))
        if so:
            so_file_id = so.id
            so_file_name = so.path

    trace = Trace(so_file_id=so_file_id, so_file_name=so_file_name)
    db.add(trace)
    await db.flush()

    instructions_data = data.get("instructions", [])
    calls_data = data.get("calls", [])
    memory_data = data.get("memory_deltas", [])
    registers_data = data.get("registers", [])
    jni_data = data.get("jni_calls", [])

    for item in instructions_data:
        db.add(Instruction(
            trace_id=trace.id,
            seq=item.get("seq", 0),
            thread_id=item.get("thread_id", 0),
            address=item.get("address", 0),
            is_branch=item.get("is_branch", False),
            branch_taken=item.get("branch_taken", False),
            timestamp=item.get("timestamp"),
            opcode=item.get("opcode"),
        ))

    for item in calls_data:
        db.add(CallTrace(
            trace_id=trace.id,
            seq=item.get("seq", 0),
            thread_id=item.get("thread_id", 0),
            event_type=item.get("event_type", "Call"),
            caller_address=item.get("caller_address", 0),
            callee_address=item.get("callee_address", 0),
            callee_func_name=item.get("callee_func_name"),
            depth=item.get("depth", 0),
        ))

    for item in memory_data:
        db.add(MemoryDelta(
            trace_id=trace.id,
            seq=item.get("seq", 0),
            thread_id=item.get("thread_id", 0),
            page_address=item.get("page_address", 0),
            delta_type=item.get("delta_type", "FullPage"),
            prev_content_hash=item.get("prev_content_hash", ""),
        ))

    for item in registers_data:
        db.add(RegisterState(
            trace_id=trace.id,
            seq=item.get("seq", 0),
            thread_id=item.get("thread_id", 0),
            gp_regs=item.get("gp_regs", []),
            sp=item.get("sp", 0),
            pc=item.get("pc", 0),
            nzcv=item.get("nzcv", 0),
        ))

    for item in jni_data:
        db.add(JniCall(
            trace_id=trace.id,
            seq=item.get("seq", 0),
            thread_id=item.get("thread_id", 0),
            direction=item.get("direction", "JavaToNative"),
            java_class=item.get("java_class", ""),
            java_method=item.get("java_method", ""),
            java_signature=item.get("java_signature", ""),
            native_address=item.get("native_address", 0),
        ))

    trace.instruction_count = len(instructions_data)
    trace.call_count = len(calls_data)
    trace.memory_delta_count = len(memory_data)

    await db.commit()
    await db.refresh(trace)
    return _trace_out(trace)


@router.get("/{trace_id}/instructions", response_model=list[InstructionOut])
async def query_instructions(
    trace_id: int,
    thread_id: Optional[int] = Query(None),
    address: Optional[str] = Query(None),
    from_seq: Optional[int] = Query(None),
    to_seq: Optional[int] = Query(None),
    limit: int = Query(100, le=10000),
    db: AsyncSession = Depends(get_db),
    _=Depends(require_auth),
):
    q = select(Instruction).where(Instruction.trace_id == trace_id)
    if thread_id is not None:
        q = q.where(Instruction.thread_id == thread_id)
    if address is not None:
        q = q.where(Instruction.address == int(address, 0))
    if from_seq is not None:
        q = q.where(Instruction.seq >= from_seq)
    if to_seq is not None:
        q = q.where(Instruction.seq <= to_seq)
    q = q.order_by(Instruction.seq).limit(limit)
    result = await db.execute(q)
    rows = result.scalars().all()
    return [InstructionOut(
        seq=r.seq, thread_id=r.thread_id, address=r.address,
        is_branch=r.is_branch, branch_taken=r.branch_taken,
        timestamp=r.timestamp, opcode=r.opcode,
    ) for r in rows]


@router.get("/{trace_id}/call-chain", response_model=list[CallTraceOut])
async def query_call_chain(
    trace_id: int,
    thread_id: Optional[int] = Query(None),
    limit: int = Query(100, le=10000),
    db: AsyncSession = Depends(get_db),
    _=Depends(require_auth),
):
    q = select(CallTrace).where(CallTrace.trace_id == trace_id)
    if thread_id is not None:
        q = q.where(CallTrace.thread_id == thread_id)
    q = q.order_by(CallTrace.seq).limit(limit)
    result = await db.execute(q)
    rows = result.scalars().all()
    return [CallTraceOut(
        id=r.id, thread_id=r.thread_id, event_type=r.event_type,
        caller_address=r.caller_address, callee_address=r.callee_address,
        callee_func_name=r.callee_func_name, seq=r.seq, depth=r.depth,
    ) for r in rows]


@router.get("/{trace_id}/call-stack/{seq}", response_model=list[StackFrameOut])
async def rebuild_call_stack(
    trace_id: int,
    seq: int,
    thread_id: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    _=Depends(require_auth),
):
    q = select(CallTrace).where(
        CallTrace.trace_id == trace_id,
        CallTrace.seq <= seq,
    )
    if thread_id is not None:
        q = q.where(CallTrace.thread_id == thread_id)
    q = q.order_by(CallTrace.seq)
    result = await db.execute(q)
    calls = result.scalars().all()

    # Simple stack reconstruction
    stack: list[dict] = []
    for c in calls:
        if c.event_type in ("Call", "TailCall"):
            stack.append({
                "func_name": c.callee_func_name,
                "entry_address": c.callee_address,
                "call_site": c.caller_address,
                "call_seq": c.seq,
                "depth": c.depth,
            })
        elif c.event_type == "Return" and stack:
            stack.pop()

    return stack


@router.get("/{trace_id}/memory/{seq}", response_model=list[MemoryDeltaOut])
async def query_memory_snapshot(
    trace_id: int,
    seq: int,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_auth),
):
    q = select(MemoryDelta).where(
        MemoryDelta.trace_id == trace_id,
        MemoryDelta.seq <= seq,
    ).order_by(MemoryDelta.seq.desc()).limit(200)
    result = await db.execute(q)
    rows = result.scalars().all()
    return [MemoryDeltaOut(
        id=r.id, seq=r.seq, thread_id=r.thread_id,
        page_address=r.page_address, delta_type=r.delta_type,
        prev_content_hash=r.prev_content_hash,
    ) for r in rows]


@router.get("/{trace_id}/memory/{seq}/{address}", response_model=MemoryValueOut)
async def query_memory_value(
    trace_id: int,
    seq: int,
    address: str,
    db: AsyncSession = Depends(get_db),
    _=Depends(require_auth),
):
    addr = int(address, 0)
    q = select(MemoryDelta).where(
        MemoryDelta.trace_id == trace_id,
        MemoryDelta.seq <= seq,
        MemoryDelta.page_address == (addr & ~0xFFF),
    ).order_by(MemoryDelta.seq.desc()).limit(1)
    result = await db.execute(q)
    delta = result.scalar_one_or_none()
    if delta and delta.data:
        offset = addr & 0xFFF
        chunk = delta.data[offset:offset + 8]
        return {"address": addr, "value": list(chunk), "size": len(chunk)}
    return {"address": addr, "value": [], "size": 0}


@router.get("/{trace_id}/registers/{seq}", response_model=list[RegisterStateOut])
async def query_registers(
    trace_id: int,
    seq: int,
    thread_id: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    _=Depends(require_auth),
):
    q = select(RegisterState).where(
        RegisterState.trace_id == trace_id,
        RegisterState.seq <= seq,
    )
    if thread_id is not None:
        q = q.where(RegisterState.thread_id == thread_id)
    q = q.order_by(RegisterState.seq.desc()).limit(1)
    result = await db.execute(q)
    rows = result.scalars().all()
    return [RegisterStateOut(
        seq=r.seq,
        gp_regs=r.gp_regs if isinstance(r.gp_regs, list) else [],
        sp=r.sp, pc=r.pc, nzcv=r.nzcv,
    ) for r in rows]


@router.get("/{trace_id}/jni-calls", response_model=list[JniCallOut])
async def query_jni_calls(
    trace_id: int,
    thread_id: Optional[int] = Query(None),
    direction: Optional[str] = Query(None),
    limit: int = Query(100, le=10000),
    db: AsyncSession = Depends(get_db),
    _=Depends(require_auth),
):
    q = select(JniCall).where(JniCall.trace_id == trace_id)
    if thread_id is not None:
        q = q.where(JniCall.thread_id == thread_id)
    if direction is not None:
        q = q.where(JniCall.direction == direction)
    q = q.order_by(JniCall.seq).limit(limit)
    result = await db.execute(q)
    rows = result.scalars().all()
    return [JniCallOut(
        id=r.id, seq=r.seq, thread_id=r.thread_id,
        direction=r.direction, java_class=r.java_class,
        java_method=r.java_method, java_signature=r.java_signature,
        native_address=r.native_address,
    ) for r in rows]


def _trace_out(t: Trace) -> dict:
    return {
        "id": t.id,
        "so_file_id": t.so_file_id,
        "so_file_name": t.so_file_name,
        "instruction_count": t.instruction_count,
        "call_count": t.call_count,
        "memory_delta_count": t.memory_delta_count,
        "created_at": t.created_at.timestamp(),
    }
