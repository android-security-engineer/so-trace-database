from datetime import datetime
from sqlalchemy import String, Integer, BigInteger, Boolean, DateTime, LargeBinary, ForeignKey, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class Trace(Base):
    __tablename__ = "traces"

    id: Mapped[int] = mapped_column(primary_key=True)
    so_file_id: Mapped[int | None] = mapped_column(ForeignKey("so_files.id", ondelete="SET NULL"), nullable=True)
    so_file_name: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    instruction_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    call_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    memory_delta_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    instructions: Mapped[list["Instruction"]] = relationship("Instruction", back_populates="trace", cascade="all, delete-orphan")
    call_traces: Mapped[list["CallTrace"]] = relationship("CallTrace", back_populates="trace", cascade="all, delete-orphan")
    memory_deltas: Mapped[list["MemoryDelta"]] = relationship("MemoryDelta", back_populates="trace", cascade="all, delete-orphan")
    register_states: Mapped[list["RegisterState"]] = relationship("RegisterState", back_populates="trace", cascade="all, delete-orphan")
    jni_calls: Mapped[list["JniCall"]] = relationship("JniCall", back_populates="trace", cascade="all, delete-orphan")


class Instruction(Base):
    __tablename__ = "instructions"

    id: Mapped[int] = mapped_column(primary_key=True)
    trace_id: Mapped[int] = mapped_column(ForeignKey("traces.id", ondelete="CASCADE"), nullable=False)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    thread_id: Mapped[int] = mapped_column(Integer, nullable=False)
    address: Mapped[int] = mapped_column(BigInteger, nullable=False)
    is_branch: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    branch_taken: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    timestamp: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    opcode: Mapped[str | None] = mapped_column(String(64), nullable=True)

    trace: Mapped["Trace"] = relationship("Trace", back_populates="instructions")


class CallTrace(Base):
    __tablename__ = "call_traces"

    id: Mapped[int] = mapped_column(primary_key=True)
    trace_id: Mapped[int] = mapped_column(ForeignKey("traces.id", ondelete="CASCADE"), nullable=False)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    thread_id: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(16), nullable=False)
    caller_address: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    callee_address: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    callee_func_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    trace: Mapped["Trace"] = relationship("Trace", back_populates="call_traces")


class MemoryDelta(Base):
    __tablename__ = "memory_deltas"

    id: Mapped[int] = mapped_column(primary_key=True)
    trace_id: Mapped[int] = mapped_column(ForeignKey("traces.id", ondelete="CASCADE"), nullable=False)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    thread_id: Mapped[int] = mapped_column(Integer, nullable=False)
    page_address: Mapped[int] = mapped_column(BigInteger, nullable=False)
    delta_type: Mapped[str] = mapped_column(String(16), nullable=False, default="FullPage")
    prev_content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    data: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    trace: Mapped["Trace"] = relationship("Trace", back_populates="memory_deltas")


class RegisterState(Base):
    __tablename__ = "register_states"

    id: Mapped[int] = mapped_column(primary_key=True)
    trace_id: Mapped[int] = mapped_column(ForeignKey("traces.id", ondelete="CASCADE"), nullable=False)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    thread_id: Mapped[int] = mapped_column(Integer, nullable=False)
    gp_regs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=list)
    sp: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    pc: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    nzcv: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    trace: Mapped["Trace"] = relationship("Trace", back_populates="register_states")


class JniCall(Base):
    __tablename__ = "jni_calls"

    id: Mapped[int] = mapped_column(primary_key=True)
    trace_id: Mapped[int] = mapped_column(ForeignKey("traces.id", ondelete="CASCADE"), nullable=False)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    thread_id: Mapped[int] = mapped_column(Integer, nullable=False)
    direction: Mapped[str] = mapped_column(String(16), nullable=False)
    java_class: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    java_method: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    java_signature: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    native_address: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    trace: Mapped["Trace"] = relationship("Trace", back_populates="jni_calls")
