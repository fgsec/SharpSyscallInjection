using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

using static SharpSysCall.Win32;

namespace SharpSysCall {
	class Syscall {

        static byte[] basicASM =
           {
            0x4C, 0x8B, 0xD1,               // mov r10, rcx
            0xB8, 0xFF, 0x00, 0x00, 0x00,   // mov eax, FUNC(0xFF)
            0x0F, 0x05,                     // syscall
            0xC3                            // ret
		};

        static byte bNtCreateThreadEx = 0xc1;
        static byte bNtWriteVirtualMemory = 0x3a;
        static byte bNtAllocateVirtualMemory = 0x18;

        public struct Delegates {

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate NtStatus NtCreateThreadEx(ref IntPtr threadHandle, UInt32 desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize, IntPtr attributeList);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate NtStatus NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToWrite, ref UInt32 NumberOfBytesWritten);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate NtStatus NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, UInt32 ZeroBits, ref UInt32 RegionSize, UInt32 AllocationType, UInt32 Protect);
        }


        public static NtStatus NtCreateThreadEx(ref IntPtr threadHandle, UInt32 desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize,IntPtr attributeList) {

            byte[] syscall = basicASM;
            syscall[4] = bNtCreateThreadEx; 

            unsafe {
                fixed (byte* ptr = syscall) {
                    IntPtr memoryAddress = (IntPtr)ptr;
                    if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect)) {
                        throw new Win32Exception();
                    }
                    Delegates.NtCreateThreadEx assembledFunction = (Delegates.NtCreateThreadEx)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtCreateThreadEx));
                    return (NtStatus)assembledFunction(ref threadHandle, desiredAccess, objectAttributes, processHandle, startAddress, parameter, inCreateSuspended, stackZeroBits, stackZeroBits, maximumStackSize, attributeList);
                }
            }
        }

        public static NtStatus NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToWrite, ref UInt32 NumberOfBytesWritten) {

            byte[] syscall = basicASM;
            syscall[4] = bNtWriteVirtualMemory;

            unsafe {
                fixed (byte* ptr = syscall) {
                    IntPtr memoryAddress = (IntPtr)ptr;
                    if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect)) {
                        throw new Win32Exception();
                    }
                    Delegates.NtWriteVirtualMemory assembledFunction = (Delegates.NtWriteVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtWriteVirtualMemory));
                    return (NtStatus)assembledFunction(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, ref NumberOfBytesWritten);
                }
            }
        }

        public static NtStatus NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, UInt32 ZeroBits, ref UInt32 RegionSize, UInt32 AllocationType, UInt32 Protect) {

            byte[] syscall = basicASM;
            syscall[4] = bNtAllocateVirtualMemory;

            unsafe {
                fixed (byte* ptr = syscall) {
                    IntPtr memoryAddress = (IntPtr)ptr;
                    if (!VirtualProtect(memoryAddress, (UIntPtr)syscall.Length, (uint)AllocationProtect.PAGE_EXECUTE_READWRITE, out uint lpflOldProtect)) {
                        throw new Win32Exception();
                    }
                    Delegates.NtAllocateVirtualMemory assembledFunction = (Delegates.NtAllocateVirtualMemory)Marshal.GetDelegateForFunctionPointer(memoryAddress, typeof(Delegates.NtAllocateVirtualMemory));
                    return (NtStatus)assembledFunction(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);
                }
            }
        }




    }
}
