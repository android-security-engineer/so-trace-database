// API type definitions

export interface SOFile {
  id: number
  path: string
  arch: string
  file_size: number
  md5: string
  sha256: string
  loaded_base_address: number
  created_at: number
}

export interface SOFunction {
  id: number
  name: string
  offset: number
  size: number
  is_jni: boolean
  is_imported: boolean
  is_exported: boolean
}

export interface InstructionTrace {
  seq: number
  thread_id: number
  address: number
  is_branch: boolean
  branch_taken: boolean
  timestamp?: number
  opcode?: string
}

export interface CallTrace {
  id: number
  thread_id: number
  event_type: 'Call' | 'Return' | 'TailCall'
  caller_address: number
  callee_address: number
  callee_func_name?: string
  seq: number
  depth: number
}

export interface MemoryDelta {
  id: number
  seq: number
  thread_id: number
  page_address: number
  delta_type: 'FullPage' | 'PageDelta' | 'ByteLevel'
  prev_content_hash: string
}

export interface MemoryValue {
  address: number
  value: number[]
  size: number
}

export interface RegisterState {
  seq: number
  gp_regs: number[]
  sp: number
  pc: number
  nzcv: number
}

export interface JNICall {
  id: number
  seq: number
  thread_id: number
  direction: 'JavaToNative' | 'NativeToJava'
  java_class: string
  java_method: string
  java_signature: string
  native_address: number
}

export interface StackFrame {
  func_id?: number
  func_name?: string
  entry_address: number
  call_site: number
  call_seq: number
  depth: number
}

// Thread trace types — comprehensive thread tracking for Android SO analysis

export interface ThreadInfo {
  thread_id: number
  pthread_id?: number
  parent_thread_id: number
  create_step: number
  exit_step?: number
  name?: string
  stack_base: number
  stack_size: number
  tls_addr: number
  is_jni_attached: boolean
}

export type ThreadState =
  | 'Running'
  | 'Runnable'
  | 'Blocked'
  | 'WaitingForLock'
  | 'WaitingForFutex'
  | 'WaitingForCondvar'
  | 'WaitingForIO'
  | 'Sleeping'
  | 'Terminated'

export type SyncEventType =
  | 'MutexLock' | 'MutexLocked' | 'MutexUnlock' | 'MutexTryLock'
  | 'FutexWait' | 'FutexWake' | 'FutexWakeCount'
  | 'CondvarWait' | 'CondvarSignal' | 'CondvarBroadcast'
  | 'RwLockRead' | 'RwLockWrite' | 'RwLockUnlock'
  | 'BarrierWait' | 'SemWait' | 'SemPost'

export type SyncResult = 'Success' | 'Timeout' | 'WouldBlock' | 'Error' | 'Interrupted'

export interface ThreadSyncEvent {
  step: number
  thread_id: number
  sync_type: SyncEventType
  sync_object_addr: number
  result: SyncResult
  wait_duration_ns?: number
}

export type SwitchReason = 'Yield' | 'Preemption' | 'Blocking' | 'Interrupt' | 'TimeSliceExpired' | 'Migration' | 'Other'

export interface ContextSwitch {
  step: number
  from_thread: number
  to_thread: number
  switch_reason: SwitchReason
  cpu_core?: number
}

export interface ThreadStats {
  thread_id: number
  steps_executed: number
  running_time_ns?: number
  context_switch_count: number
  sync_event_count: number
  lock_acquire_count: number
  lock_contention_count: number
  avg_lock_wait_ns?: number
  function_call_count: number
}

// Thread analysis result types — high-level analysis for SO reverse engineering

/** Detected race condition */
export interface RaceCondition {
  address: number
  first_step: number
  first_thread: number
  second_step: number
  second_thread: number
  first_is_write: boolean
  second_is_write: boolean
  confidence: number
  description: string
}

/** Detected potential deadlock */
export interface DeadlockRisk {
  lock_cycle: number[]
  threads: number[]
  violation_steps: number[]
  description: string
}

/** Lock contention analysis result */
export interface LockContentionInfo {
  lock_address: number
  acquire_count: number
  contention_count: number
  contention_ratio: number
  total_wait_ns: number
  avg_wait_ns: number
  max_wait_ns: number
  contending_threads: number[]
}

/** Thread-function association */
export interface ThreadFunctionAssoc {
  thread_id: number
  function_address: number
  call_count: number
  first_call_step: number
  last_call_step: number
}

/** Thread safety classification */
export type ThreadSafety = 'ThreadSafe' | 'PotentiallyUnsafe' | 'Unsafe' | 'Unknown'

/** Function thread safety info */
export interface FunctionThreadSafety {
  function_address: number
  calling_thread_count: number
  calling_threads: number[]
  safety: ThreadSafety
  race_count: number
  sync_event_count: number
}

/** Thread data flow */
export interface ThreadDataFlow {
  from_thread: number
  to_thread: number
  address: number
  write_step: number
  read_step: number
  is_synchronized: boolean
}

/** Producer-consumer pattern */
export interface ProducerConsumerPattern {
  producer_thread: number
  consumer_thread: number
  shared_addresses: number[]
  cycle_count: number
  avg_latency_steps: number
  sync_mechanism?: number
}

/** Comprehensive thread analysis result */
export interface ThreadAnalysisResult {
  race_conditions: RaceCondition[]
  deadlock_risks: DeadlockRisk[]
  lock_contentions: LockContentionInfo[]
  thread_function_assocs: ThreadFunctionAssoc[]
  function_safety: FunctionThreadSafety[]
  data_flows: ThreadDataFlow[]
  producer_consumer_patterns: ProducerConsumerPattern[]
}

export interface TraceSession {
  id: number
  so_file_id: number
  so_file_name: string
  instruction_count: number
  call_count: number
  memory_delta_count: number
  created_at: number
}

export interface Stats {
  so_file_count: number
  trace_count: number
  total_instructions: number
  total_calls: number
  total_memory_deltas: number
  database_size: number
}

export interface AuthResponse {
  access_token: string
  refresh_token: string
  expires_in: number
}

export interface SetupRequest {
  username: string
  password: string
}

export interface LoginRequest {
  username: string
  password: string
}
