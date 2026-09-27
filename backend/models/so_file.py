from datetime import datetime
from sqlalchemy import String, Integer, BigInteger, Boolean, DateTime, LargeBinary, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class SoFile(Base):
    __tablename__ = "so_files"

    id: Mapped[int] = mapped_column(primary_key=True)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    arch: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    md5: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    loaded_base_address: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    binary_data: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    functions: Mapped[list["SoFunction"]] = relationship("SoFunction", back_populates="so_file", cascade="all, delete-orphan")
    symbols: Mapped[list["SoSymbol"]] = relationship("SoSymbol", back_populates="so_file", cascade="all, delete-orphan")
    segments: Mapped[list["SoSegment"]] = relationship("SoSegment", back_populates="so_file", cascade="all, delete-orphan")


class SoFunction(Base):
    __tablename__ = "so_functions"

    id: Mapped[int] = mapped_column(primary_key=True)
    so_file_id: Mapped[int] = mapped_column(ForeignKey("so_files.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    offset: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_jni: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_imported: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_exported: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    so_file: Mapped["SoFile"] = relationship("SoFile", back_populates="functions")


class SoSymbol(Base):
    __tablename__ = "so_symbols"

    id: Mapped[int] = mapped_column(primary_key=True)
    so_file_id: Mapped[int] = mapped_column(ForeignKey("so_files.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    address: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    symbol_type: Mapped[str] = mapped_column(String(32), nullable=False, default="NOTYPE")

    so_file: Mapped["SoFile"] = relationship("SoFile", back_populates="symbols")


class SoSegment(Base):
    __tablename__ = "so_segments"

    id: Mapped[int] = mapped_column(primary_key=True)
    so_file_id: Mapped[int] = mapped_column(ForeignKey("so_files.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    vaddr: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    filesz: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    memsz: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    flags: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    so_file: Mapped["SoFile"] = relationship("SoFile", back_populates="segments")
