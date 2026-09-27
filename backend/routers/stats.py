from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.so_file import SoFile
from models.trace import Trace, Instruction, CallTrace, MemoryDelta
from middleware.auth import require_auth

router = APIRouter(prefix="/stats", tags=["stats"])


class StatsOut(BaseModel):
    so_file_count: int
    trace_count: int
    total_instructions: int
    total_calls: int
    total_memory_deltas: int
    database_size: int


@router.get("", response_model=StatsOut)
async def get_stats(db: AsyncSession = Depends(get_db), _=Depends(require_auth)):
    so_count = await db.scalar(select(func.count()).select_from(SoFile)) or 0
    trace_count = await db.scalar(select(func.count()).select_from(Trace)) or 0
    instr_count = await db.scalar(select(func.sum(Trace.instruction_count))) or 0
    call_count = await db.scalar(select(func.sum(Trace.call_count))) or 0
    mem_count = await db.scalar(select(func.sum(Trace.memory_delta_count))) or 0

    try:
        db_size = await db.scalar(text("SELECT pg_database_size(current_database())"))
    except Exception:
        db_size = 0

    return {
        "so_file_count": so_count,
        "trace_count": trace_count,
        "total_instructions": instr_count,
        "total_calls": call_count,
        "total_memory_deltas": mem_count,
        "database_size": db_size or 0,
    }
