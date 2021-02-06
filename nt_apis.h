#include <Windows.h>
#include "nt_defs.h"

#define STATUS_SUCCESS				((NTSTATUS)0x00000000L) // ntsubauth
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) == STATUS_SUCCESS)
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define PS_INHERIT_HANDLES          4
#define RTL_USER_PROC_PARAMS_NORMALIZED     0x00000001
#define RTL_MAX_DRIVE_LETTERS 32

typedef NTSTATUS NTAPI NTCREATETRANSACTION(
	_Out_     PHANDLE TransactionHandle,
	_In_      ACCESS_MASK DesiredAccess,
	_In_opt_  POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_  LPGUID Uow,
	_In_opt_  HANDLE TmHandle,
	_In_opt_  ULONG CreateOptions,
	_In_opt_  ULONG IsolationLevel,
	_In_opt_  ULONG IsolationFlags,
	_In_opt_  PLARGE_INTEGER Timeout,
	_In_opt_  PUNICODE_STRING Description
	);
typedef NTCREATETRANSACTION FAR * LPNTCREATETRANSACTION;

typedef NTSTATUS NTAPI NTALLOCATEVIRTUALMEMORY(
	_In_        HANDLE ProcessHandle,
	_Inout_     PVOID *BaseAddress,
	_In_        ULONG_PTR ZeroBits,
	_Inout_     PSIZE_T RegionSize,
	_In_        ULONG AllocationType,
	_In_        ULONG Protect
	);
typedef NTALLOCATEVIRTUALMEMORY FAR * LPNTALLOCATEVIRTUALMEMORY;

typedef NTSTATUS NTAPI NTCREATESECTION(
	_Out_		PHANDLE SectionHandle,
	_In_		ACCESS_MASK DesiredAccess,
	_In_opt_	POBJECT_ATTRIBUTES ObjectAttributes,
	_In_opt_	PLARGE_INTEGER MaximumSize,
	_In_		ULONG SectionPageProtection,
	_In_		ULONG AllocationAttributes,
	_In_opt_	HANDLE FileHandle
	);
typedef NTCREATESECTION FAR * LPNTCREATESECTION;

typedef NTSTATUS NTAPI NTMAPVIEWOFSECTION(
    _In_        HANDLE          SectionHandle,
    _In_        HANDLE          ProcessHandle,
    _Inout_     PVOID           *BaseAddress,
    _In_        ULONG_PTR       ZeroBits,
    _In_        SIZE_T          CommitSize,
    _Inout_opt_ PLARGE_INTEGER  SectionOffset,
    _Inout_     PSIZE_T         ViewSize,
    _In_        SECTION_INHERIT InheritDisposition,
    _In_        ULONG           AllocationType,
    _In_        ULONG           Win32Protect
	);

typedef NTMAPVIEWOFSECTION FAR * LPNTMAPVIEWOFSECTION;

typedef NTSTATUS NTAPI NTUNMAPVIEWOFSECTION(
	_In_ HANDLE               ProcessHandle,
	_In_ PVOID                BaseAddress
	);

typedef NTUNMAPVIEWOFSECTION FAR * LPNTUNMAPVIEWOFSECTION;

typedef NTSTATUS NTAPI NTROLLBACKTRANSACTION(
    _In_ HANDLE  TransactionHandle,
    _In_ BOOLEAN Wait);
typedef NTROLLBACKTRANSACTION FAR * LPNTROLLBACKTRANSACTION;

typedef NTSTATUS NTAPI NTCLOSE(
	_In_ HANDLE Handle
	);
typedef NTCLOSE FAR * LPNTCLOSE;

typedef NTSTATUS NTAPI NTCREATEPROCESSEX(
    _Out_    PHANDLE ProcessHandle,
    _In_     ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_     HANDLE ParentProcess,
    _In_     ULONG Flags,
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE ExceptionPort,
    _In_     BOOLEAN InJob);
typedef NTCREATEPROCESSEX FAR * LPNTCREATEPROCESSEX;

typedef NTSTATUS NTAPI NTQUERYINFORMATIONPROCESS(
	_In_		HANDLE ProcessHandle,
	_In_		PROCESSINFOCLASS ProcessInformationClass,
	_Out_		PVOID ProcessInformation,
	_In_		ULONG ProcessInformationLength,
	_Out_opt_	PULONG ReturnLength
	);
typedef NTQUERYINFORMATIONPROCESS FAR * LPNTQUERYINFORMATIONPROCESS;

typedef NTSTATUS NTAPI NTREADVIRTUALMEMORY(
	_In_		HANDLE ProcessHandle,
	_In_opt_	PVOID BaseAddress,
	_Out_		PVOID Buffer,
	_In_		SIZE_T BufferSize,
	_Out_opt_	PSIZE_T NumberOfBytesRead
	);
typedef NTREADVIRTUALMEMORY FAR * LPNTREADVIRTUALMEMORY;

typedef NTSTATUS NTAPI NTWRITEVIRTUALMEMORY(
	_In_        HANDLE ProcessHandle,
	_In_opt_    PVOID BaseAddress,
	_In_        VOID *Buffer,
	_In_        SIZE_T BufferSize,
	_Out_opt_   PSIZE_T NumberOfBytesWritten
	);
typedef NTWRITEVIRTUALMEMORY FAR * LPNTWRITEVIRTUALMEMORY;

typedef NTSTATUS NTAPI NTCREATETHREADEX(
    _Out_ PHANDLE hThread,
    _In_  ACCESS_MASK DesiredAccess,
    _In_  LPVOID ObjectAttributes,
    _In_  HANDLE ProcessHandle,
    _In_  LPTHREAD_START_ROUTINE lpStartAddress,
    _In_  LPVOID lpParameter,
    _In_  BOOL CreateSuspended,
    _In_  DWORD StackZeroBits,
    _In_  DWORD SizeOfStackCommit,
    _In_  DWORD SizeOfStackReserve,
    _Out_ LPVOID lpBytesBuffer);
typedef NTCREATETHREADEX FAR * LPNTCREATETHREADEX;

typedef NTSTATUS NTAPI NTFREEVIRTUALMEMORY(
	_In_       HANDLE ProcessHandle,
	_Inout_    PVOID *BaseAddress,
	_Inout_    PSIZE_T RegionSize,
	_In_       ULONG FreeType
	);
typedef NTFREEVIRTUALMEMORY FAR * LPNTFREEVIRTUALMEMORY;

typedef NTSTATUS NTAPI RTLCREATEUSERTHREAD(
	IN HANDLE               ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN              CreateSuspended,
	IN ULONG                StackZeroBits,
	IN OUT PULONG           StackReserved,
	IN OUT PULONG           StackCommit,
	IN PVOID                StartAddress,
	IN PVOID                StartParameter OPTIONAL,
	OUT PHANDLE             ThreadHandle,
	OUT PCLIENT_ID          ClientID
);

typedef NTSTATUS NTAPI RTLCREATEPROCESSPARAMETERSEX(
    _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    _In_ PUNICODE_STRING ImagePathName,
    _In_opt_ PUNICODE_STRING DllPath,
    _In_opt_ PUNICODE_STRING CurrentDirectory,
    _In_opt_ PUNICODE_STRING CommandLine,
    _In_opt_ PVOID Environment,
    _In_opt_ PUNICODE_STRING WindowTitle,
    _In_opt_ PUNICODE_STRING DesktopInfo,
    _In_opt_ PUNICODE_STRING ShellInfo,
    _In_opt_ PUNICODE_STRING RuntimeData,
    _In_ ULONG Flags);
typedef RTLCREATEPROCESSPARAMETERSEX FAR * LPRTLCREATEPROCESSPARAMETERSEX;

typedef NTSTATUS NTAPI RTLDESTROYPROCESSPARAMETERS(
    _In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters
    );
typedef RTLDESTROYPROCESSPARAMETERS FAR * LPRTLDESTROYPROCESSPARAMETERS;

typedef PIMAGE_NT_HEADERS NTAPI RTLIMAGENTHEADER(
	_In_ PVOID Base
	);
typedef RTLIMAGENTHEADER FAR * LPRTLIMAGENTHEADER;


typedef PVOID NTAPI RTLINITUNICODESTRING(
	_Inout_	PUNICODE_STRING DestinationString,
    _In_opt_ PCWSTR SourceString
	);
typedef RTLINITUNICODESTRING FAR * LPRTLINITUNICODESTRING;