from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.so_file import SoFile, SoFunction, SoSymbol, SoSegment
from utils.elf import parse_elf, compute_md5, compute_sha256
from middleware.auth import require_auth

router = APIRouter(prefix="/so-files", tags=["so-files"])


class SoFileOut(BaseModel):
    id: int
    path: str
    arch: str
    file_size: int
    md5: str
    sha256: str
    loaded_base_address: int
    created_at: float

    model_config = {"from_attributes": True}


class SoFunctionOut(BaseModel):
    id: int
    name: str
    offset: int
    size: int
    is_jni: bool
    is_imported: bool
    is_exported: bool

    model_config = {"from_attributes": True}


class SoSymbolOut(BaseModel):
    id: int
    name: str
    address: int
    symbol_type: str

    model_config = {"from_attributes": True}


class SoSegmentOut(BaseModel):
    id: int
    name: str
    vaddr: int
    filesz: int
    memsz: int
    flags: int

    model_config = {"from_attributes": True}


@router.get("", response_model=list[SoFileOut])
async def list_so_files(db: AsyncSession = Depends(get_db), _=Depends(require_auth)):
    result = await db.execute(select(SoFile).order_by(SoFile.created_at.desc()))
    files = result.scalars().all()
    return [_to_out(f) for f in files]


@router.get("/{so_id}", response_model=SoFileOut)
async def get_so_file(so_id: int, db: AsyncSession = Depends(get_db), _=Depends(require_auth)):
    f = await db.get(SoFile, so_id)
    if not f:
        raise HTTPException(status_code=404, detail="Not found")
    return _to_out(f)


@router.post("", response_model=SoFileOut, status_code=201)
async def create_so_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    _=Depends(require_auth),
):
    data = await file.read()
    filename = file.filename or "unknown.so"

    md5 = compute_md5(data)
    sha256 = compute_sha256(data)

    # Check duplicate by sha256
    existing = await db.scalar(select(SoFile).where(SoFile.sha256 == sha256))
    if existing:
        return _to_out(existing)

    try:
        parsed = parse_elf(data)
    except Exception:
        parsed = {"arch": "unknown", "functions": [], "symbols": [], "segments": []}

    so = SoFile(
        path=filename,
        arch=parsed["arch"],
        file_size=len(data),
        md5=md5,
        sha256=sha256,
        loaded_base_address=0,
        binary_data=data,
    )
    db.add(so)
    await db.flush()

    for fn in parsed["functions"]:
        db.add(SoFunction(so_file_id=so.id, **fn))
    for sym in parsed["symbols"]:
        db.add(SoSymbol(so_file_id=so.id, **sym))
    for seg in parsed["segments"]:
        db.add(SoSegment(so_file_id=so.id, **seg))

    await db.commit()
    await db.refresh(so)
    return _to_out(so)


@router.get("/{so_id}/functions", response_model=list[SoFunctionOut])
async def get_functions(so_id: int, db: AsyncSession = Depends(get_db), _=Depends(require_auth)):
    result = await db.execute(select(SoFunction).where(SoFunction.so_file_id == so_id))
    return result.scalars().all()


@router.get("/{so_id}/symbols", response_model=list[SoSymbolOut])
async def get_symbols(so_id: int, db: AsyncSession = Depends(get_db), _=Depends(require_auth)):
    result = await db.execute(select(SoSymbol).where(SoSymbol.so_file_id == so_id))
    return result.scalars().all()


@router.get("/{so_id}/segments", response_model=list[SoSegmentOut])
async def get_segments(so_id: int, db: AsyncSession = Depends(get_db), _=Depends(require_auth)):
    result = await db.execute(select(SoSegment).where(SoSegment.so_file_id == so_id))
    return result.scalars().all()


def _to_out(f: SoFile) -> dict:
    return {
        "id": f.id,
        "path": f.path,
        "arch": f.arch,
        "file_size": f.file_size,
        "md5": f.md5,
        "sha256": f.sha256,
        "loaded_base_address": f.loaded_base_address,
        "created_at": f.created_at.timestamp(),
    }
