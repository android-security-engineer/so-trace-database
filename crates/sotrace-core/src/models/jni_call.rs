//! JNI call trace record model

use serde::{Deserialize, Serialize};

/// JNI call direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JNICallDirection {
    /// Java calling into Native
    JavaToNative,
    /// Native calling into Java (via JNI callback)
    NativeToJava,
}

/// A JNI boundary call record
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JNICall {
    /// Unique ID (primary key)
    pub id: u64,
    /// Sequence number when this call occurred
    pub seq: u64,
    /// Thread ID
    pub thread_id: u32,
    /// Call direction
    pub direction: JNICallDirection,
    /// Java fully-qualified class name
    pub java_class: String,
    /// Java method name
    pub java_method: String,
    /// Java method signature (parameter and return types)
    pub java_signature: String,
    /// Native function ID (foreign key → SOFunction, optional)
    pub native_func_id: Option<u32>,
    /// Native function address
    pub native_address: u64,
    /// JNIEnv pointer value (optional)
    pub jni_env_address: Option<u64>,
}
