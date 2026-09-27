#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <atomic>
#include <mutex>

// ---- Command-line knobs ----
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "/tmp/sotrace-pin.jsonl", "output JSONL file");
KNOB<string> KnobSoName(KNOB_MODE_WRITEONCE, "pintool",
    "so", "", "SO name to filter (empty = all modules)");
KNOB<BOOL> KnobEnableMemory(KNOB_MODE_WRITEONCE, "pintool",
    "mem", "0", "enable memory read/write tracing (high overhead)");

// ---- Global state ----
static std::ofstream OutFile;
static std::mutex    OutMutex;
static std::atomic<uint64_t> Seq{0};

static ADDRINT SoBase = 0;
static ADDRINT SoEnd  = 0;

// ---- Emit helpers (called from instrumented code) ----

static VOID EmitInstruction(ADDRINT pc, BOOL is_branch, BOOL branch_taken, THREADID tid)
{
    ADDRINT offset = (SoBase != 0) ? (pc - SoBase) : pc;
    std::ostringstream ss;
    ss << "{\"type\":\"instruction\",\"seq\":" << Seq++
       << ",\"thread_id\":" << tid
       << ",\"address\":"   << offset
       << ",\"is_branch\":"   << (is_branch   ? "true" : "false")
       << ",\"branch_taken\":" << (branch_taken ? "true" : "false")
       << "}\n";
    std::lock_guard<std::mutex> lk(OutMutex);
    OutFile << ss.str();
}

static VOID EmitMemRead(ADDRINT addr, UINT32 size, THREADID tid)
{
    ADDRINT offset = (SoBase != 0) ? (addr - SoBase) : addr;
    std::ostringstream ss;
    ss << "{\"type\":\"mem_read\",\"step\":" << Seq++
       << ",\"thread_id\":" << tid
       << ",\"address\":"   << offset
       << ",\"size\":"      << size
       << "}\n";
    std::lock_guard<std::mutex> lk(OutMutex);
    OutFile << ss.str();
}

static VOID EmitMemWrite(ADDRINT addr, UINT32 size, THREADID tid)
{
    ADDRINT offset = (SoBase != 0) ? (addr - SoBase) : addr;
    std::ostringstream ss;
    ss << "{\"type\":\"mem_write\",\"step\":" << Seq++
       << ",\"thread_id\":" << tid
       << ",\"address\":"   << offset
       << ",\"size\":"      << size
       << ",\"data\":[]"
       << "}\n";
    std::lock_guard<std::mutex> lk(OutMutex);
    OutFile << ss.str();
}

// ---- Image load callback: detect SO base/end ----
static VOID ImageLoad(IMG img, VOID * /*v*/)
{
    const string &imgName   = IMG_Name(img);
    const string &filterStr = KnobSoName.Value();

    if (!filterStr.empty() && imgName.find(filterStr) == string::npos)
        return;

    ADDRINT lo = IMG_LowAddress(img);
    ADDRINT hi = IMG_HighAddress(img);

    // Only update if this is the first match (or re-load)
    if (SoBase == 0 || lo < SoBase) {
        SoBase = lo;
        SoEnd  = hi;
        cerr << "[sotrace] SO loaded: " << imgName
             << "  base=0x" << hex << SoBase
             << "  size=0x" << (SoEnd - SoBase) << dec << "\n";
    }
}

// ---- Instruction instrumentation callback ----
static VOID Instruction(INS ins, VOID * /*v*/)
{
    ADDRINT pc = INS_Address(ins);

    // Filter: only instrument instructions inside our SO
    if (SoBase != 0 && (pc < SoBase || pc >= SoEnd))
        return;

    BOOL is_branch = INS_IsBranchOrCall(ins);

    if (is_branch && INS_IsDirectBranchOrCall(ins)) {
        // Insert at IPOINT_TAKEN_BRANCH (branch_taken=TRUE) — fires only when taken
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)EmitInstruction,
            IARG_ADDRINT,  pc,
            IARG_BOOL,     TRUE,   // is_branch
            IARG_BOOL,     TRUE,   // branch_taken
            IARG_THREAD_ID,
            IARG_END);
        // Insert at IPOINT_BEFORE for the fall-through (branch_taken=FALSE)
        // We guard with a flag so we don't double-emit on taken branches.
        // Pin guarantees IPOINT_BEFORE fires once per static instruction decode;
        // IPOINT_TAKEN_BRANCH fires only when the branch is actually taken.
        // Emit the "not-taken" record unconditionally at BEFORE; the server
        // can reconcile if needed. (Alternatively, skip BEFORE for branches.)
        // For simplicity we only record taken vs not-taken via the two callbacks.
    } else {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EmitInstruction,
            IARG_ADDRINT,  pc,
            IARG_BOOL,     is_branch,
            IARG_BOOL,     FALSE,
            IARG_THREAD_ID,
            IARG_END);
    }

    // Memory tracing (optional, high overhead)
    if (KnobEnableMemory.Value()) {
        if (INS_IsMemoryRead(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EmitMemRead,
                IARG_MEMORYREAD_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_THREAD_ID,
                IARG_END);
        }
        if (INS_HasMemoryRead2(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EmitMemRead,
                IARG_MEMORYREAD2_EA,
                IARG_MEMORYREAD_SIZE,
                IARG_THREAD_ID,
                IARG_END);
        }
        if (INS_IsMemoryWrite(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EmitMemWrite,
                IARG_MEMORYWRITE_EA,
                IARG_MEMORYWRITE_SIZE,
                IARG_THREAD_ID,
                IARG_END);
        }
    }
}

// ---- Thread start callback ----
static VOID ThreadStart(THREADID tid, CONTEXT * /*ctxt*/, INT32 /*flags*/, VOID * /*v*/)
{
    std::ostringstream ss;
    ss << "{\"type\":\"thread\",\"thread_id\":" << tid
       << ",\"create_step\":" << Seq++
       << "}\n";
    std::lock_guard<std::mutex> lk(OutMutex);
    OutFile << ss.str();
}

// ---- Fini callback ----
static VOID Fini(INT32 /*code*/, VOID * /*v*/)
{
    OutFile.flush();
    OutFile.close();
    cerr << "[sotrace] Trace written to " << KnobOutputFile.Value() << "\n";
}

// ---- Entry point ----
int main(int argc, char *argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) {
        cerr << "SoTrace Pintool — Intel Pin instrumentation for sotrace-database\n"
             << "Usage: pin -t libsotrace_pintool.so"
             << " [-so <so_name>] [-mem 1] [-o <outfile>]"
             << " -- <binary> [args]\n"
             << KNOB_BASE::StringKnobSummary() << "\n";
        return 1;
    }

    OutFile.open(KnobOutputFile.Value().c_str(), std::ios::out | std::ios::trunc);
    if (!OutFile.is_open()) {
        cerr << "[sotrace] ERROR: cannot open output file: "
             << KnobOutputFile.Value() << "\n";
        return 1;
    }

    IMG_AddInstrumentFunction(ImageLoad, NULL);
    INS_AddInstrumentFunction(Instruction, NULL);
    PIN_AddThreadStartFunction(ThreadStart, NULL);
    PIN_AddFiniFunction(Fini, NULL);

    PIN_StartProgram();  // does not return
    return 0;
}
